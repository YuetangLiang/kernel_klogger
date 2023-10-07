#!/bin/bash

echo ---- inserting module
insmod klogger.ko

MA=$(grep klogger /proc/devices | awk '{print $1}')

echo ---- testing module
mknod testlog c ${MA} 10240 -m 0666
echo "testing testlog c ${MA} 10240 -m 0666. with RANDOM:"$RANDOM > testlog
dd if=./testlog of=/dev/stdout iflag=nonblock  2> /dev/null
rm testlog

echo ---- removing module
rmmod klogger

