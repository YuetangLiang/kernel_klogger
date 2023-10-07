klogger
==================
## testcase
```bash
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
```

### Create klogger

   ```bash
   modprobe klogger
   lsmod
   ```

### Remove klogger

   1. `rmmod klogger`
   2. `modprobe -r klogger`

### Create logfile
   get MAJOR:
   ```bash
   grep klogger /proc/devices
   ```

   create 10MB buffer:
   ```bash
   mknod /tmp/testlog c 491 10240 -m 0666
   ```

### Read/Write logfile

   1. block read:
   ```bash
   cat /tmp/testlog | hexdump -v
   ```

   2. nonblock read:
   ```bash
   time dd if=/tmp/testlog of=/tmp/saved-log-4K iflag=nonblock bs=4K count=1 2>/dev/null
   ```

   3. write profiling(10MB/5ms)
   ```bash
   time dd if=/dev/zero of=/tmp/testlog bs=1M count=10 2> /dev/null
   ```

   4. read profiling(10MB/5ms)
   ```bash
   time dd if=/tmp/testlog of=/dev/null iflag=nonblock bs=1M count=10 2> /dev/null
   ```
