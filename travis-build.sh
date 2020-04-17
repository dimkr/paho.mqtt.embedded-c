#!/bin/bash

set -e

rm -rf build.paho
meson build.paho
cd build.paho
echo "travis build dir $TRAVIS_BUILD_DIR pwd $PWD"
ninja
python ../test/mqttsas2.py localhost 1883 1885 &
meson test -v
kill %1
killall mosquitto
