// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>

#include "openssl/ssl.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/tlsio_openssl_compact.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/dns_async.h"
#include "azure_c_shared_utility/socket_async.h"
#include "azure_c_shared_utility/singlylinkedlist.h"
#include "azure_c_shared_utility/crt_abstractions.h"

typedef struct
{
	unsigned char* bytes;
	size_t size;
	size_t unsent_size;
	ON_SEND_COMPLETE on_send_complete;
	void* callback_context;
} PENDING_TRANSMISSION;

/* Codes_SRS_TLSIO_30_003: [ Tlsio adapter implementations shall define and observe the internally defined  TLSIO_OPERATION_TIMEOUT_SECONDS  timeout value for opening, closing, and sending processes: ]*/
// This value is considered an emergency limit rather than a useful tuning parameter,
// so it is not adjustable via the more expensive get / set options system
#ifndef TLSIO_OPERATION_TIMEOUT_SECONDS
#define TLSIO_OPERATION_TIMEOUT_SECONDS 40
#endif // !TLSIO_OPERATION_TIMEOUT_SECONDS

#define MAX_VALID_PORT 0xffff

/* Codes_SRS_TLSIO_30_004: [ Tlsio implementations which use an internal buffer to pass data into the  on_bytes_received  callback shall define the size of this buffer with the internally defined  TLSIO_RECEIVE_BUFFER_SIZE  value ]*/
// The TLSIO_RECEIVE_BUFFER_SIZE has very little effect on performance, and is kept small
// to minimize memory consumption.
#ifndef TLSIO_RECEIVE_BUFFER_SIZE
#define TLSIO_RECEIVE_BUFFER_SIZE 64
#endif // !TLSIO_RECEIVE_BUFFER_SIZE


typedef enum TLSIO_STATE_TAG
{
	TLSIO_STATE_CLOSED,
	TLSIO_STATE_OPENING_WAITING_DNS,
	TLSIO_STATE_OPENING_WAITING_SOCKET,
	TLSIO_STATE_OPENING_WAITING_SSL,
	TLSIO_STATE_OPEN,
	TLSIO_STATE_ERROR,
} TLSIO_STATE;

// This structure definition is mirrored in the unit tests, so if you change
// this struct, keep it in sync with the one in tlsio_openssl_compact_ut.c
typedef struct TLS_IO_INSTANCE_TAG
{
	uint16_t struct_size;
	ON_BYTES_RECEIVED on_bytes_received;
	ON_IO_ERROR on_io_error;
	ON_IO_OPEN_COMPLETE on_open_complete;
	void* on_bytes_received_context;
	void* on_io_error_context;
	void* on_open_complete_context;
	SSL* ssl;
	SSL_CTX* ssl_context;
	TLSIO_STATE tlsio_state;
	DNS_ASYNC_HANDLE dns;
	char* hostname;
	uint16_t port;
	time_t operation_timeout_end_time;
	SOCKET_ASYNC_HANDLE sock;
	SINGLYLINKEDLIST_HANDLE pending_transmission_list;
} TLS_IO_INSTANCE;

#ifndef NO_LOGGING
static const char* null_tlsio_message = "NULL tlsio";
static const char* allocate_fail_message = "malloc failed";
#endif

static void enter_tlsio_error_state(TLS_IO_INSTANCE* tls_io_instance)
{
    Frog();
	if (tls_io_instance->tlsio_state != TLSIO_STATE_ERROR)
	{
		tls_io_instance->tlsio_state = TLSIO_STATE_ERROR;
		tls_io_instance->on_io_error(tls_io_instance->on_io_error_context);
	}
}

static void enter_open_error_state(TLS_IO_INSTANCE* tls_io_instance)
{
	enter_tlsio_error_state(tls_io_instance);
	// on_open_complete has already been checked for non-NULL
	/* Codes_SRS_TLSIO_30_005: [ When the adapter enters TLSIO_STATE_EXT_ERROR it shall call the  on_io_error function and pass the on_io_error_context that were supplied in  tlsio_open . ]*/
	tls_io_instance->on_open_complete(tls_io_instance->on_open_complete_context, IO_OPEN_ERROR);
}

// Return true if a message was available to remove
static bool close_and_destroy_head_message(TLS_IO_INSTANCE* tls_io_instance, IO_SEND_RESULT send_result)
{
	bool result;
	tls_io_instance->operation_timeout_end_time = 0;
	if (send_result == IO_SEND_ERROR)
	{
		/* Codes_SRS_TLSIO_30_095: [ If the send process fails before sending all of the bytes in an enqueued message, the tlsio_dowork shall call the message's on_send_complete along with its associated callback_context and IO_SEND_ERROR. ]*/
		enter_tlsio_error_state(tls_io_instance);
	}
	LIST_ITEM_HANDLE head_pending_io = singlylinkedlist_get_head_item(tls_io_instance->pending_transmission_list);
	if (head_pending_io != NULL)
	{
		PENDING_TRANSMISSION* head_message = (PENDING_TRANSMISSION*)singlylinkedlist_item_get_value(head_pending_io);
		// on_send_complete is checked for NULL during PENDING_TRANSMISSION creation
		/* Codes_SRS_TLSIO_30_095: [ If the send process fails before sending all of the bytes in an enqueued message, the tlsio_dowork shall call the message's on_send_complete along with its associated callback_context and IO_SEND_ERROR. ]*/
		head_message->on_send_complete(head_message->callback_context, send_result);

		free(head_message->bytes);
		free(head_message);
		if (singlylinkedlist_remove(tls_io_instance->pending_transmission_list, head_pending_io) != 0)
		{
			// This particular situation is a bizarre and unrecoverable internal error
			/* Codes_SRS_TLSIO_30_094: [ If the send process encounters an internal error or calls on_send_complete with IO_SEND_ERROR due to either failure or timeout, it shall also call on_io_error and pass in the associated on_io_error_context. ]*/
			enter_tlsio_error_state(tls_io_instance);
			LogError("Unrecoverable program bug: unable to remove message from list");
		}
		result = true;
	}
	else
	{
		result = false;
	}
	return result;
}

/* Codes_SRS_TLSIO_30_081: [ If the connection process takes longer than the internally defined TLSIO_OPERATION_TIMEOUT_SECONDS, tlsio_dowork shall log an error, call on_io_open_complete with the on_io_open_complete_context parameter provided in tlsio_open and IO_OPEN_ERROR, and enter TLSIO_STATE_EX_ERROR. ]*/
static void check_for_open_timeout(TLS_IO_INSTANCE* tls_io_instance)
{
	time_t now = get_time(NULL);
	if (now > tls_io_instance->operation_timeout_end_time)
	{
		// This has taken too long, so bail out
		LogInfo("Timeout while opening tlsio");
		enter_open_error_state(tls_io_instance);
	}
}

static void internal_close(TLS_IO_INSTANCE* tls_io_instance)
{
	/* Codes_SRS_TLSIO_30_051: [ The tlsio_openssl_compact_close shall forcibly close any existing ssl connection. ]*/
	if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
	{
		// From the OpenSSL manual pages: "According to the TLS standard, it is acceptable 
		// for an application to only send its shutdown alert and then close the 
		// underlying connection without waiting for the peer's response...". It goes
		// on to say that waiting for shutdown only makes sense if the underlying
		// connection is being re-used, which we do not do. So there's no need
		// to wait for shutdown.
		(void)SSL_shutdown(tls_io_instance->ssl);
	}

	if (tls_io_instance->dns != NULL)
	{
		dns_async_destroy(tls_io_instance->dns);
		tls_io_instance->dns = NULL;
	}
	if (tls_io_instance->ssl != NULL)
	{
		SSL_free(tls_io_instance->ssl);
		tls_io_instance->ssl = NULL;
	}
	if (tls_io_instance->ssl_context != NULL)
	{
		SSL_CTX_free(tls_io_instance->ssl_context);
		tls_io_instance->ssl_context = NULL;
	}
	if (tls_io_instance->sock >= 0)
	{
		// The underlying socket API does not support waiting for close
		// to complete, so it isn't possible to do so.
		socket_async_destroy(tls_io_instance->sock);
		tls_io_instance->sock = -1;
	}

	/* Codes_SRS_TLSIO_30_056: [ If tlsio_openssl_compact_close is called while there are unsent messages in the queue, the tlsio_openssl_compact_close shall call each message's on_send_complete, passing its associated callback_context and IO_SEND_CANCELLED. ]*/
	while (close_and_destroy_head_message(tls_io_instance, IO_SEND_CANCELLED));
	// singlylinkedlist_destroy gets called in the main destroy

	tls_io_instance->on_bytes_received = NULL;
	tls_io_instance->on_io_error = NULL;
	tls_io_instance->on_bytes_received_context = NULL;
	tls_io_instance->on_io_error_context = NULL;
	tls_io_instance->tlsio_state = TLSIO_STATE_CLOSED;
	tls_io_instance->on_open_complete = NULL;
	tls_io_instance->on_open_complete_context = NULL;
}

// This method tests for hard errors returned from either SSL_write or SSL_connect.
// Returns 
//     0 for SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
//     The actual error for other errors (real failures)
static int is_hard_ssl_error(SSL* ssl, int callReturn)
{
	int result = SSL_get_error(ssl, callReturn);
	if (result == SSL_ERROR_WANT_READ || result == SSL_ERROR_WANT_WRITE)
	{
		result = 0;
	}
	return result;
}

void tlsio_openssl_destroy(CONCRETE_IO_HANDLE tls_io)
{
	TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
	if (tls_io_instance == NULL)
	{
		/* Codes_SRS_TLSIO_30_020: [ If tlsio_handle is NULL, tlsio_destroy shall do nothing. ]*/
		LogError(null_tlsio_message);
	}
	else
	{
		if (tls_io_instance->tlsio_state != TLSIO_STATE_CLOSED)
		{
			/* Codes_SRS_TLSIO_30_022: [ If the adapter is in any state other than TLSIO_STATE_EX_CLOSED when tlsio_destroy is called, the adapter shall enter TLSIO_STATE_EX_CLOSING and then enter TLSIO_STATE_EX_CLOSED before completing the destroy process. ]*/
			LogError("tlsio_openssl_destroy called while not in TLSIO_STATE_CLOSED.");
			internal_close(tls_io_instance);
		}
		/* Codes_SRS_TLSIO_30_021: [ The tlsio_destroy shall release all allocated resources and then release tlsio_handle. ]*/
		if (tls_io_instance->hostname != NULL)
		{
			free(tls_io_instance->hostname);
			tls_io_instance->hostname = NULL;
		}

		if (tls_io_instance->pending_transmission_list != NULL)
		{
			/* Pending messages were cleared in internal_close */
			singlylinkedlist_destroy(tls_io_instance->pending_transmission_list);
			tls_io_instance->pending_transmission_list = NULL;
		}

		free(tls_io_instance);
	}
}

/* Codes_SRS_TLSIO_30_010: [ The tlsio_create shall allocate and initialize all necessary resources and return an instance of the tlsio_openssl_compact. ]*/
CONCRETE_IO_HANDLE tlsio_openssl_create(void* io_create_parameters)
{
	/* Codes_SRS_TLSIO_30_012: [ The tlsio_create shall receive the connection configuration as a TLSIO_CONFIG* in io_create_parameters. ]*/
	TLSIO_CONFIG* tls_io_config = (TLSIO_CONFIG*)io_create_parameters;
	TLS_IO_INSTANCE* result;

	if (io_create_parameters == NULL)
	{
		/* Codes_SRS_TLSIO_30_013: [ If the io_create_parameters value is NULL, tlsio_create shall log an error and return NULL. ]*/
		LogError("NULL tls_io_config");
		result = NULL;
	}
	else
	{
		if (tls_io_config->hostname == NULL)
		{
			/* Codes_SRS_TLSIO_30_014: [ If the hostname member of io_create_parameters value is NULL, tlsio_create shall log an error and return NULL. ]*/
			LogError("NULL tls_io_config->hostname");
			result = NULL;
		}
		else
		{
			if (tls_io_config->port < 0 || tls_io_config->port > MAX_VALID_PORT)
			{
				/* Codes_SRS_TLSIO_30_015: [ If the port member of io_create_parameters value is less than 0 or greater than 0xffff, tlsio_create shall log an error and return NULL. ]*/
				LogError("tls_io_config->port out of range");
				result = NULL;
			}
			else
			{
				result = malloc(sizeof(TLS_IO_INSTANCE));
				if (result == NULL)
				{
					/* Codes_SRS_TLSIO_30_011: [ If any resource allocation fails, tlsio_create shall return NULL. ]*/
					LogError(allocate_fail_message);
				}
				else
				{
					memset(result, 0, sizeof(TLS_IO_INSTANCE));
					result->struct_size = sizeof(TLS_IO_INSTANCE);
					result->port = (uint16_t)tls_io_config->port;
					result->tlsio_state = TLSIO_STATE_CLOSED;
					result->sock = SOCKET_ASYNC_INVALID_SOCKET;
					result->hostname = NULL;
					result->dns = NULL;
					result->pending_transmission_list = NULL;
					result->operation_timeout_end_time = 0;
					/* Codes_SRS_TLSIO_30_016: [ tlsio_create shall make a copy of the hostname member of io_create_parameters to allow deletion of hostname immediately after the call. ]*/
					int ms_result = mallocAndStrcpy_s(&result->hostname, tls_io_config->hostname);
					if (ms_result != 0)
					{
						/* Codes_SRS_TLSIO_30_011: [ If any resource allocation fails, tlsio_create shall return NULL. ]*/
						LogError(allocate_fail_message);
						tlsio_openssl_destroy(result);
						result = NULL;
					}
					else
					{
						// Create the message queue
						result->pending_transmission_list = singlylinkedlist_create();
						if (result->pending_transmission_list == NULL)
						{
							/* Codes_SRS_TLSIO_30_011: [ If any resource allocation fails, tlsio_create shall return NULL. ]*/
							LogError("Failed singlylinkedlist_create");
							tlsio_openssl_destroy(result);
							result = NULL;
						}
					}
				}
			}
		}
	}

	return (CONCRETE_IO_HANDLE)result;
}


int tlsio_openssl_open(CONCRETE_IO_HANDLE tls_io,
	ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context,
	ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context,
	ON_IO_ERROR on_io_error, void* on_io_error_context)
{

	int result;
	if (on_io_open_complete == NULL)
	{
		/* Codes_SRS_TLSIO_30_031: [ If the on_io_open_complete parameter is NULL, tlsio_open shall log an error and return FAILURE. ]*/
		LogError("Required parameter on_io_open_complete is NULL");
		result = __FAILURE__;
	}
	else
	{
		if (tls_io == NULL)
		{
			/* Codes_SRS_TLSIO_30_030: [ If the tlsio_handle parameter is NULL, tlsio_open shall log an error and return FAILURE. ]*/
			result = __FAILURE__;
			LogError(null_tlsio_message);
		}
		else
		{
			TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
			tls_io_instance->operation_timeout_end_time = get_time(NULL) + TLSIO_OPERATION_TIMEOUT_SECONDS;

			if (on_bytes_received == NULL)
			{
				/* Codes_SRS_TLSIO_30_032: [ If the on_bytes_received parameter is NULL, tlsio_open shall log an error and return FAILURE. ]*/
				LogError("Required parameter on_bytes_received is NULL");
				result = __FAILURE__;
			}
			else
			{
				if (on_io_error == NULL)
				{
					/* Codes_SRS_TLSIO_30_033: [ If the on_io_error parameter is NULL, tlsio_open shall log an error and return FAILURE. ]*/
					LogError("Required parameter on_io_error is NULL");
					result = __FAILURE__;
				}
				else
				{
					if (tls_io_instance->tlsio_state != TLSIO_STATE_CLOSED)
					{
						/* Codes_SRS_TLSIO_30_037: [ If the adapter is in any state other than TLSIO_STATE_EXT_CLOSED when tlsio_open  is called, it shall log an error, and return FAILURE. ]*/
						LogError("Invalid tlsio_state. Expected state is TLSIO_STATE_CLOSED.");
						result = __FAILURE__;
					}
					else
					{
						tls_io_instance->dns = dns_async_create(tls_io_instance->hostname, NULL);
						if (tls_io_instance->dns == NULL)
						{
							/* Codes_SRS_TLSIO_30_038: [ If tlsio_open fails to enter TLSIO_STATE_EX_OPENING it shall return FAILURE. ]*/
							// Error already logged
							result = __FAILURE__;
						}
						else
						{
							/* Codes_SRS_TLSIO_30_034: [ The tlsio_open shall store the provided on_bytes_received, on_bytes_received_context, on_io_error, on_io_error_context, on_io_open_complete, and on_io_open_complete_context parameters for later use as specified and tested per other line entries in this document. ]*/
							tls_io_instance->on_bytes_received = on_bytes_received;
							tls_io_instance->on_bytes_received_context = on_bytes_received_context;

							tls_io_instance->on_io_error = on_io_error;
							tls_io_instance->on_io_error_context = on_io_error_context;

							tls_io_instance->on_open_complete = on_io_open_complete;
							tls_io_instance->on_open_complete_context = on_io_open_complete_context;

							/* Codes_SRS_TLSIO_30_035: [ On tlsio_open success the adapter shall enter TLSIO_STATE_EX_OPENING and return 0. ]*/
							// All the real work happens in dowork
							tls_io_instance->tlsio_state = TLSIO_STATE_OPENING_WAITING_DNS;
							result = 0;
						}
					}
				}
			}
		}

		if (result != 0)
		{
			/* Codes_SRS_TLSIO_30_039: [ If the tlsio_open returns FAILURE it shall call on_io_open_complete with the provided on_io_open_complete_context and IO_OPEN_ERROR. ]*/
			on_io_open_complete(on_io_open_complete_context, IO_OPEN_ERROR);
		}
	}

	return result;
}


int tlsio_openssl_close(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
	int result;

	TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
	if (tls_io == NULL)
	{
		/* Codes_SRS_TLSIO_30_050: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_close shall log an error and return FAILURE. ]*/
		LogError(null_tlsio_message);
		result = __FAILURE__;
	}
	else
	{
		if (on_io_close_complete == NULL)
		{
			/* Codes_SRS_TLSIO_30_055: [ If the on_io_close_complete parameter is NULL, tlsio_openssl_compact_close shall log an error and return FAILURE. ]*/
			LogError("NULL on_io_close_complete");
			result = __FAILURE__;
		}
		else
		{
			if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN &&
				tls_io_instance->tlsio_state != TLSIO_STATE_ERROR)
			{
				/* Codes_SRS_TLSIO_30_053: [ If the adapter is in any state other than TLSIO_STATE_EXT_OPEN or TLSIO_STATE_EXT_ERROR  tlsio_close  shall log an error and return FAILURE. ]*/
				LogError("tlsio_openssl_close has been called when in neither TLSIO_STATE_OPEN nor TLSIO_STATE_ERROR.");
				result = __FAILURE__;
			}
			else
			{
				/* Codes_SRS_TLSIO_30_056: [ On success the adapter shall enter TLSIO_STATE_EX_CLOSING. ]*/
				/* Codes_SRS_TLSIO_30_051: [ On success, if the underlying TLS does not support asynchronous closing, then the adapter shall enter TLSIO_STATE_EX_CLOSED immediately after entering TLSIO_STATE_EX_CLOSING. ]*/
				/* Codes_SRS_TLSIO_30_052: [ On success tlsio_close shall return 0. ]*/
				internal_close(tls_io_instance);
				/* Codes_SRS_TLSIO_30_057: [ When the closing process is complete, tlsio_openssl_compact_close shall call on_io_close_complete and pass the callback_context as a parameter. ]*/
				on_io_close_complete(callback_context);
				result = 0;
			}
		}
	}

	return result;
}

int tlsio_openssl_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
	int result;
	if (on_send_complete == NULL)
	{
		/* Codes_SRS_TLSIO_30_062: [ If the on_send_complete is NULL, tlsio_openssl_compact_send shall log the error and return FAILURE. ]*/
		result = __FAILURE__;
		LogError("NULL on_send_complete");
	}
	else
	{
		TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
		if (tls_io_instance == NULL)
		{
			/* Codes_SRS_TLSIO_30_060: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_send shall log an error and return FAILURE. ]*/
			result = __FAILURE__;
			LogError(null_tlsio_message);
		}
		else
		{
			if (buffer == NULL)
			{
				/* Codes_SRS_TLSIO_30_061: [ If the buffer is NULL, tlsio_openssl_compact_send shall log the error and return FAILURE. ]*/
				result = __FAILURE__;
				LogError("NULL buffer.");
			}
			else
			{
				if (size == 0)
				{
					/* Codes_SRS_TLSIO_30_067: [ If the  size  is 0,  tlsio_send  shall log the error and return FAILURE. ]*/
					result = __FAILURE__;
					LogError("0 size.");
				}
				else
				{
					if (tls_io_instance->tlsio_state != TLSIO_STATE_OPEN)
					{
						/* Codes_SRS_TLSIO_30_065: [ If tlsio_openssl_compact_open has not been called or the opening process has not been completed, tlsio_openssl_compact_send shall log an error and return FAILURE. ]*/
						result = __FAILURE__;
						LogError("tlsio_openssl_send without a prior successful open.");
					}
					else
					{
						PENDING_TRANSMISSION* pending_transmission = (PENDING_TRANSMISSION*)malloc(sizeof(PENDING_TRANSMISSION));
						if (pending_transmission == NULL)
						{
							/* Codes_SRS_TLSIO_30_064: [ If the supplied message cannot be enqueued for transmission, tlsio_openssl_compact_send shall return FAILURE. ]*/
							result = __FAILURE__;
							LogError(allocate_fail_message);
						}
						else
						{
							/* Codes_SRS_TLSIO_30_063: [ The tlsio_openssl_compact_send shall enqueue for transmission the on_send_complete, the callback_context, the size, and the contents of buffer. ]*/
							/* Codes_SRS_TLSIO_30_067: [ If the size is 0, on_send_complete shall accept and process the message normally. ]*/
							// Accept messages of length zero, but don't allocate memory for them
							if (size > 0)
							{
								pending_transmission->bytes = (unsigned char*)malloc(size);
							}
							else
							{
								pending_transmission->bytes = NULL;
							}

							if (pending_transmission->bytes == NULL)
							{
								/* Codes_SRS_TLSIO_30_064: [ If the supplied message cannot be enqueued for transmission, tlsio_openssl_compact_send shall return FAILURE. ]*/
								LogError(allocate_fail_message);
								free(pending_transmission);
								result = __FAILURE__;
							}
							else
							{
								pending_transmission->size = size;
								pending_transmission->unsent_size = size;
								pending_transmission->on_send_complete = on_send_complete;
								pending_transmission->callback_context = callback_context;
								(void)memcpy(pending_transmission->bytes, buffer, size);

								if (singlylinkedlist_add(tls_io_instance->pending_transmission_list, pending_transmission) == NULL)
								{
									/* Codes_SRS_TLSIO_30_064: [ If the supplied message cannot be enqueued for transmission, tlsio_openssl_compact_send shall return FAILURE. ]*/
									LogError("Unable to add socket to pending list.");
									free(pending_transmission->bytes);
									free(pending_transmission);
									result = __FAILURE__;
								}
								else
								{
									/* Codes_SRS_TLSIO_30_063: [ On success,  tlsio_send  shall enqueue for transmission the  on_send_complete , the  callback_context , the  size , and the contents of  buffer  and then return 0. ]*/
									result = 0;
								}
							}
						}
					}
				}
			}
		}
		if (result != 0)
		{
			/* Codes_SRS_TLSIO_30_066: [ On failure, a non-NULL on_send_complete shall be called with callback_context and IO_SEND_ERROR. ]*/
			on_send_complete(callback_context, IO_SEND_ERROR);
		}
	}
	return result;
}

static void dowork_read(TLS_IO_INSTANCE* tls_io_instance)
{
	// TRANSFER_BUFFER_SIZE is not very important because if the message is bigger
	// then the framework just calls dowork repeatedly until it gets everything. So
	// a bigger buffer would just use memory without buying anything.
	// Putting this buffer in a small function also allows it to exist on the stack
	// rather than adding to heap fragmentation.
	unsigned char buffer[TLSIO_RECEIVE_BUFFER_SIZE];
	int rcv_bytes;

	if (tls_io_instance->tlsio_state == TLSIO_STATE_OPEN)
	{
		// SSL_read is not checked for errors because the "no data" condition is reported as a 
		// failure, but the docs do not guarantee that it will always be the same failure,
		// so we have no reliable wayto distinguish "no data" from something else.
		rcv_bytes = SSL_read(tls_io_instance->ssl, buffer, sizeof(buffer));
		if (rcv_bytes > 0)
		{
			// tls_io_instance->on_bytes_received was already checked for NULL
			// in the call to tlsio_openssl_open
			/* Codes_SRS_TLSIO_30_100: [ If the TLS connection is able to provide received data, tlsio_dowork shall read this data and call on_bytes_received with the pointer to the buffer containing the data, the number of bytes received, and the on_bytes_received_context. ]*/
			tls_io_instance->on_bytes_received(tls_io_instance->on_bytes_received_context, buffer, rcv_bytes);
		}
		else
		{
			/* Codes_SRS_TLSIO_30_102: [ If the TLS connection receives no data then tlsio_dowork shall not call the on_bytes_received callback. ]*/
		}
	}
}


static int create_ssl(TLS_IO_INSTANCE* tls_io_instance)
{
	int result;
	int ret;

	{
		tls_io_instance->ssl_context = SSL_CTX_new(TLSv1_2_client_method());
		if (tls_io_instance->ssl_context == NULL)
		{
			/* Codes_SRS_TLSIO_30_082: [ If the connection process fails for any reason, tlsio_dowork shall log an error, call on_io_open_complete with the on_io_open_complete_context parameter provided in tlsio_open and IO_OPEN_ERROR, and enter TLSIO_STATE_EX_ERROR. ]*/
			result = __FAILURE__;
			LogError("create new SSL CTX failed");
		}
		else
		{
			tls_io_instance->ssl = SSL_new(tls_io_instance->ssl_context);
			if (tls_io_instance->ssl == NULL)
			{
				/* Codes_SRS_TLSIO_30_082: [ If the connection process fails for any reason, tlsio_dowork shall log an error, call on_io_open_complete with the on_io_open_complete_context parameter provided in tlsio_open and IO_OPEN_ERROR, and enter TLSIO_STATE_EX_ERROR. ]*/
				result = __FAILURE__;
				LogError("SSL_new failed");
			}
			else
			{
				// returns 1 on success
				ret = SSL_set_fd(tls_io_instance->ssl, tls_io_instance->sock);
				if (ret != 1)
				{
					/* Codes_SRS_TLSIO_30_082: [ If the connection process fails for any reason, tlsio_dowork shall log an error, call on_io_open_complete with the on_io_open_complete_context parameter provided in tlsio_open and IO_OPEN_ERROR, and enter TLSIO_STATE_EX_ERROR. ]*/
					result = __FAILURE__;
					LogError("SSL_set_fd failed");
				}
				else
				{
					result = 0;
				}
			}
		}
	}

	return result;
}

static void dowork_send(TLS_IO_INSTANCE* tls_io_instance)
{
	LIST_ITEM_HANDLE first_pending_io = singlylinkedlist_get_head_item(tls_io_instance->pending_transmission_list);
	if (first_pending_io != NULL)
	{
		PENDING_TRANSMISSION* pending_message = (PENDING_TRANSMISSION*)singlylinkedlist_item_get_value(first_pending_io);
		// Initialize the send start time if necessary
		if (tls_io_instance->operation_timeout_end_time == 0)
		{
			tls_io_instance->operation_timeout_end_time = time(NULL) + TLSIO_OPERATION_TIMEOUT_SECONDS;
		}

		time_t now = get_time(NULL);
		if (now > tls_io_instance->operation_timeout_end_time)
		{
			/* Codes_SRS_TLSIO_30_002: [ The phrase "destroy the failed message" means that the adapter shall remove the message from the queue and destroy it after calling the message's on_send_complete along with its associated callback_context and IO_SEND_ERROR. ]*/
			/* Codes_SRS_TLSIO_30_005: [ When the adapter enters TLSIO_STATE_EXT_ERROR it shall call the  on_io_error function and pass the on_io_error_context that were supplied in  tlsio_open . ]*/
			/* Codes_SRS_TLSIO_30_092: [ If the send process for any given message takes longer than the internally defined TLSIO_OPERATION_TIMEOUT_SECONDS it shall destroy the failed message and enter TLSIO_STATE_EX_ERROR. ]*/
			LogInfo("send timeout");
			close_and_destroy_head_message(tls_io_instance, IO_SEND_ERROR);
		}
		else
		{
			uint8_t* buffer = ((uint8_t*)pending_message->bytes) +
				pending_message->size - pending_message->unsent_size;
			int write_result = SSL_write(tls_io_instance->ssl, buffer, pending_message->unsent_size);
			// https://wiki.openssl.org/index.php/Manual:SSL_write(3)

			if (write_result > 0)
			{
				pending_message->unsent_size -= write_result;
				if (pending_message->unsent_size == 0)
				{
					/* Codes_SRS_TLSIO_30_091: [ If tlsio_openssl_compact_dowork is able to send all the bytes in an enqueued message, it shall call the messages's on_send_complete along with its associated callback_context and IO_SEND_OK. ]*/
					// The whole message has been sent successfully
					close_and_destroy_head_message(tls_io_instance, IO_SEND_OK);
				}
				else
				{
					/* Codes_SRS_TLSIO_30_093: [ If the TLS connection was not able to send an entire enqueued message at once, subsequent calls to tlsio_dowork shall continue to send the remaining bytes. ]*/
					// Repeat the send on the next pass with the rest of the message
					// This empty else compiles to nothing but helps readability
				}
			}
			else
			{
				// SSL_write returned non-success. It may just be busy, or it may be broken.
				int hard_error = is_hard_ssl_error(tls_io_instance->ssl, write_result);
				if (hard_error != 0)
				{
					/* Codes_SRS_TLSIO_30_002: [ The phrase "destroy the failed message" means that the adapter shall remove the message from the queue and destroy it after calling the message's on_send_complete along with its associated callback_context and IO_SEND_ERROR. ]*/
					/* Codes_SRS_TLSIO_30_005: [ When the adapter enters TLSIO_STATE_EXT_ERROR it shall call the  on_io_error function and pass the on_io_error_context that were supplied in  tlsio_open . ]*/
					/* Codes_SRS_TLSIO_30_095: [ If the send process fails before sending all of the bytes in an enqueued message, tlsio_dowork shall destroy the failed message and enter TLSIO_STATE_EX_ERROR. ]*/
					// This is an unexpected error, and we need to bail out. Probably lost internet connection.
					LogInfo("Error from SSL_write: %d", hard_error);
					close_and_destroy_head_message(tls_io_instance, IO_SEND_ERROR);
				}
			}
		}
	}
	else
	{
		/* Codes_SRS_TLSIO_30_096: [ If there are no enqueued messages available, tlsio_openssl_compact_dowork shall do nothing. ]*/
	}
}

static void dowork_poll_dns(TLS_IO_INSTANCE* tls_io_instance)
{
	bool dns_is_complete = dns_async_is_lookup_complete(tls_io_instance->dns);

	if (dns_is_complete)
	{
		uint32_t host_ipV4_address = dns_async_get_ipv4(tls_io_instance->dns);
		dns_async_destroy(tls_io_instance->dns);
		tls_io_instance->dns = NULL;
		if (host_ipV4_address == 0)
		{
			// Transition to TSLIO_STATE_ERROR
			/* Codes_SRS_TLSIO_30_082: [ If the connection process fails for any reason, tlsio_dowork shall log an error, call on_io_open_complete with the on_io_open_complete_context parameter provided in tlsio_open and IO_OPEN_ERROR, and enter TLSIO_STATE_EX_ERROR. ]*/
			// The DNS failure has already been logged
			enter_open_error_state(tls_io_instance);
		}
		else
		{
			SOCKET_ASYNC_HANDLE sock = socket_async_create(host_ipV4_address, tls_io_instance->port, false, NULL);
			if (sock < 0)
			{
				// This is a communication interruption rather than a program bug
				/* Codes_SRS_TLSIO_30_082: [ If the connection process fails for any reason, tlsio_dowork shall log an error, call on_io_open_complete with the on_io_open_complete_context parameter provided in tlsio_open and IO_OPEN_ERROR, and enter TLSIO_STATE_EX_ERROR. ]*/
				LogInfo("Could not open the socket");
				enter_open_error_state(tls_io_instance);
			}
			else
			{
				// The socket has been created successfully, so now wait for it to
				// finish the TCP handshake.
				tls_io_instance->sock = sock;
				tls_io_instance->tlsio_state = TLSIO_STATE_OPENING_WAITING_SOCKET;
			}
		}
	}
	else
	{
		/* Codes_SRS_TLSIO_30_081: [ If the connection process takes longer than the internally defined TLSIO_OPERATION_TIMEOUT_SECONDS, tlsio_dowork shall log an error, call on_io_open_complete with the on_io_open_complete_context parameter provided in tlsio_open and IO_OPEN_ERROR, and enter TLSIO_STATE_EX_ERROR. ]*/
		check_for_open_timeout(tls_io_instance);
	}
}

static void dowork_poll_socket(TLS_IO_INSTANCE* tls_io_instance)
{
	bool is_complete;
	int result = socket_async_is_create_complete(tls_io_instance->sock, &is_complete);
	if (result != 0)
	{
		// Transition to TSLIO_STATE_ERROR
		LogInfo("socket_async_is_create_complete failure");
		enter_open_error_state(tls_io_instance);
	}
	else
	{
		if (is_complete)
		{
			// Attempt to transition to TLSIO_STATE_OPENING_WAITING_SSL
			int create_ssl_result = create_ssl(tls_io_instance);
			if (create_ssl_result != 0)
			{
				// Transition to TSLIO_STATE_ERROR
				// create_ssl already did error logging
				enter_open_error_state(tls_io_instance);
			}
			else
			{
				tls_io_instance->tlsio_state = TLSIO_STATE_OPENING_WAITING_SSL;
			}
		}
		else
		{
			/* Codes_SRS_TLSIO_30_081: [ If the connection process takes longer than the internally defined TLSIO_OPERATION_TIMEOUT_SECONDS, tlsio_dowork shall log an error, call on_io_open_complete with the on_io_open_complete_context parameter provided in tlsio_open and IO_OPEN_ERROR, and enter TLSIO_STATE_EX_ERROR. ]*/
			check_for_open_timeout(tls_io_instance);
		}
	}
}

static void dowork_poll_open_ssl(TLS_IO_INSTANCE* tls_io_instance)
{
	// https://www.openssl.org/docs/man1.0.2/ssl/SSL_connect.html

	// "If the underlying BIO is non - blocking, SSL_connect() will also 
	// return when the underlying BIO could not satisfy the needs of 
	// SSL_connect() to continue the handshake, indicating the 
	// problem by the return value -1. In this case a call to 
	// SSL_get_error() with the return value of SSL_connect() will 
	// yield SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.The calling 
	// process then must repeat the call after taking appropriate 
	// action to satisfy the needs of SSL_connect().The action 
	// depends on the underlying BIO. When using a non - blocking 
	// socket, nothing is to be done, but select() can be used to 
	// check for the required condition."

	int connect_result = SSL_connect(tls_io_instance->ssl);

	// The following note applies to the Espressif ESP32 implementation
	// of OpenSSL:
	// The manual pages seem to be incorrect. They say that 0 is a failure,
	// but by experiment, 0 is the success result, at least when using
	// SSL_set_fd instead of custom BIO.
	// https://www.openssl.org/docs/man1.0.2/ssl/SSL_connect.html
	if (connect_result == 1 || connect_result == 0)
	{
		/* Codes_SRS_TLSIO_30_080: [ The tlsio_dowork shall establish a TLS connection using the hostName and port provided during tlsio_open. ]*/
		// Connect succeeded
		tls_io_instance->tlsio_state = TLSIO_STATE_OPEN;
		/* Codes_SRS_TLSIO_30_007: [ The phrase "enter TLSIO_STATE_EXT_OPEN" means the adapter shall call the on_io_open_complete function and pass IO_OPEN_OK and the on_io_open_complete_context that was supplied in tlsio_open . ]*/
		/* Codes_SRS_TLSIO_30_083: [ If tlsio_dowork successfully opens the TLS connection it shall enter TLSIO_STATE_EX_OPEN. ]*/
		tls_io_instance->on_open_complete(tls_io_instance->on_open_complete_context, IO_OPEN_OK);
	}
	else
	{
		int hard_error = is_hard_ssl_error(tls_io_instance->ssl, connect_result);
		if (hard_error != 0)
		{
			/* Codes_SRS_TLSIO_30_082: [ If the connection process fails for any reason, tlsio_dowork shall log an error, call on_io_open_complete with the on_io_open_complete_context parameter provided in tlsio_open and IO_OPEN_ERROR, and enter TLSIO_STATE_EX_ERROR. ]*/
			LogInfo("Hard error from SSL_connect: %d", hard_error);
			enter_open_error_state(tls_io_instance);
		}
		else
		{
			/* Codes_SRS_TLSIO_30_081: [ If the connection process takes longer than the internally defined TLSIO_OPERATION_TIMEOUT_SECONDS, tlsio_dowork shall log an error, call on_io_open_complete with the on_io_open_complete_context parameter provided in tlsio_open and IO_OPEN_ERROR, and enter TLSIO_STATE_EX_ERROR. ]*/
			check_for_open_timeout(tls_io_instance);
		}
	}
}

void tlsio_openssl_dowork(CONCRETE_IO_HANDLE tls_io)
{
	TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
	if (tls_io_instance == NULL)
	{
		/* Codes_SRS_TLSIO_30_070: [ If the tlsio_handle parameter is NULL, tlsio_dowork shall do nothing except log an error. ]*/
		LogError(null_tlsio_message);
	}
	else
	{
		// This switch statement handles all of the state transitions during the opening process
		switch (tls_io_instance->tlsio_state)
		{
		case TLSIO_STATE_CLOSED:
			/* Codes_SRS_TLSIO_30_075: [ If the adapter is in TLSIO_STATE_EXT_CLOSED then  tlsio_dowork  shall do nothing. ]*/
			// Waiting to be opened, nothing to do
			break;
		case TLSIO_STATE_OPENING_WAITING_DNS:
			//LogInfo("dowork_poll_dns");
			dowork_poll_dns(tls_io_instance);
			break;
		case TLSIO_STATE_OPENING_WAITING_SOCKET:
			//LogInfo("dowork_poll_socket");
			dowork_poll_socket(tls_io_instance);
			break;
		case TLSIO_STATE_OPENING_WAITING_SSL:
			//LogInfo("dowork_poll_ssl");
			dowork_poll_open_ssl(tls_io_instance);
			break;
		case TLSIO_STATE_OPEN:
			dowork_read(tls_io_instance);
			dowork_send(tls_io_instance);
			break;
		case TLSIO_STATE_ERROR:
			/* Codes_SRS_TLSIO_30_071: [ If the adapter is in TLSIO_STATE_EXT_ERROR then tlsio_dowork shall do nothing. ]*/
			// There's nothing valid to do here but wait to be retried
			break;
		default:
			LogError("Unrecoverable program bug: unexpected internal tlsio state");
			break;
		}
	}
}

int tlsio_openssl_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value)
{
	TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
	/* Codes_SRS_TLSIO_30_120: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
	int result;
	if (tls_io_instance == NULL)
	{
		LogError(null_tlsio_message);
		result = __FAILURE__;
	}
	else
	{
		/* Codes_SRS_TLSIO_30_121: [ If the optionName parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
		if (optionName == NULL)
		{
			LogError("Required optionName parameter is NULL");
			result = __FAILURE__;
		}
		else
		{
			/* Codes_SRS_TLSIO_30_122: [ If the value parameter is NULL, tlsio_openssl_compact_setoption shall do nothing except log an error and return FAILURE. ]*/
			if (value == NULL)
			{
				LogError("Required value parameter is NULL");
				result = __FAILURE__;
			}
			else
			{
				/* Codes_SRS_TLSIO_30_123 [ The tlsio_openssl_compact_setoption shall do nothing and return 0. ]*/
				result = 0;
			}
		}
	}
	return result;
}

/* Codes_SRS_TLSIO_30_161: [ The tlsio_openssl_compact_retrieveoptions shall do nothing and return NULL. ]*/
static OPTIONHANDLER_HANDLE tlsio_openssl_retrieveoptions(CONCRETE_IO_HANDLE tls_io)
{
	TLS_IO_INSTANCE* tls_io_instance = (TLS_IO_INSTANCE*)tls_io;
	/* Codes_SRS_TLSIO_30_160: [ If the tlsio_handle parameter is NULL, tlsio_openssl_compact_retrieveoptions shall do nothing except log an error and return FAILURE. ]*/
	OPTIONHANDLER_HANDLE result;
	if (tls_io_instance == NULL)
	{
		LogError(null_tlsio_message);
		result = NULL;
	}
	else
	{
		result = NULL;
	}
	return result;
}

/* Codes_SRS_TLSIO_30_008: [ The tlsio_get_interface_description shall return the VTable IO_INTERFACE_DESCRIPTION. ]*/
static const IO_INTERFACE_DESCRIPTION tlsio_openssl_interface_description =
{
	tlsio_openssl_retrieveoptions,
	tlsio_openssl_create,
	tlsio_openssl_destroy,
	tlsio_openssl_open,
	tlsio_openssl_close,
	tlsio_openssl_send,
	tlsio_openssl_dowork,
	tlsio_openssl_setoption
};

/* Codes_SRS_TLSIO_30_001: [ The tlsio_openssl_compact shall implement and export all the Concrete functions in the VTable IO_INTERFACE_DESCRIPTION defined in the xio.h. ]*/
const IO_INTERFACE_DESCRIPTION* tlsio_openssl_compact_get_interface_description(void)
{
	return &tlsio_openssl_interface_description;
}

#ifdef TLSIO_STATE_VERIFICATION_ENABLE
#include "unit_test_api_impl.h"
#endif
