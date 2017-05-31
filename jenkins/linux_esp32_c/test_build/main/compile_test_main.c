// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_system.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event_loop.h" 
#include "esp_log.h"

#include "nvs_flash.h"
#include "iothub_client_sample_mqtt.h"



#define EXAMPLE_WIFI_SSID "not used for compile test"
#define EXAMPLE_WIFI_PASS "not used"

void app_main()
{
	// This code will not run and is just here to test compile and link
	iothub_client_sample_mqtt_run();

	printf("goodbye");
}
