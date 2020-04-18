#!/bin/bash

set -e

rm -rf build.paho
meson -Doptimization=3 -Ddebug=true --werror build.paho
cd build.paho
echo "travis build dir $TRAVIS_BUILD_DIR pwd $PWD"
ninja
python ../test/mqttsas2.py localhost 1883 1885 &
meson test -v --no-rebuild
meson configure -Db_sanitize=address
meson test -v
kill %1
