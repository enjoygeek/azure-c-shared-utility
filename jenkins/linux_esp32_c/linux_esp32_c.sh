echo "hello esp32"

 printenv

 export PATH=$ESP32_TOOLS:$PATH
 cd test_build
 make

# dir /home/jenkins
# dir /home/jenkins/esp32
# dir /home/jenkins/esp32-idf

# cd /home/jenkins/esp32-idf
# git rev-parse HEAD
# git checkout 53893297299e207029679dc99b7fb33151bdd415
# git rev-parse HEAD


