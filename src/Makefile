# Makefile for Universal Memory Dumper kernel module

obj-m += mem_dumper.o

all:
	@echo "Building Universal MemDumper kernel module..."
	@echo "Target kernel: $(shell uname -r)"
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	@echo "Cleaning build files..."
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
