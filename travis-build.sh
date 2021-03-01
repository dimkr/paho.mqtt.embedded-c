#!/bin/bash

set -e

rm -rf build.paho
meson -Doptimization=3 -Ddebug=true --werror -Db_sanitize=address build.paho
cd build.paho
echo "travis build dir $TRAVIS_BUILD_DIR pwd $PWD"
ninja
python ../test/mqttsas2.py localhost 1883 1885 &
sleep 1
meson test -v --no-rebuild
kill %1
