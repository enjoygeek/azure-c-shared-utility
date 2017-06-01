echo "hello esp32"

 printenv

dir /home/jenkins
dir /home/jenkins/esp32
dir /home/jenkins/esp32-idf

cd /home/jenkins/esp32-idf
git rev-parse HEAD
git checkout 972d1d9242bad8b2c09840794dd143c1d5ad75da
git rev-parse HEAD


