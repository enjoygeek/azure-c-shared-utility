echo "Cross-compiling a non-working ESP32 example"

export PATH=$PATH:$ESP32_TOOLS

# Verify that the ESP32 SDK is at a tested commit
pushd $IDF_PATH
git rev-parse HEAD
idf_commit=$(git rev-parse HEAD)
tested_idf_commit=53893297299e207029679dc99b7fb33151bdd415
popd
if [ $idf_commit = $tested_idf_commit ]
	then echo "ESP32 SDK commit is okay"
else 
	echo "ESP32 SDK commit is " $idf_commit
	echo "ESP32 SDK commit should be " $tested_idf_commit
	echo "Error: ESP32 SDK commit is wrong"
	exit 1
fi

pwd
cd c-utility/jenkins/linux_esp32_c/test_build
dir
#make

echo "version 02"


