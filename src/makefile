# Makefile for MemDumper kernel module

obj-m += mem_dumper.o

all:
    @echo "Building MemDumper kernel module..."
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    @echo "Cleaning build files..."
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean