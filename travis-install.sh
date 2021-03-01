#!/bin/bash

if [ "$TRAVIS_OS_NAME" == "linux" ]; then
	pip3 install "meson>=0.56.0,<0.57.0"
	# Stop any mosquitto instance which may be still running from previous runs
	sudo systemctl restart mosquitto
fi

if [ "$TRAVIS_OS_NAME" == "osx" ]; then
	brew update
	brew install openssl mosquitto
	brew services stop mosquitto
	/usr/local/sbin/mosquitto -h
	/usr/local/sbin/mosquitto &
fi
