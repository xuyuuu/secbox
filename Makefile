obj-m := sec_box.o
sec_box-objs := sec_box_init.o sec_box_blacklist.o\
	sec_box_socket.o sec_box_md5sum.o sec_box_swhook.o\
	sec_box_accesslist.o sec_box_tcpstat.o

KERNELDIR = /lib/modules/$(shell uname -r)/build/
KERNELBIT = $(shell getconf LONG_BIT)
EXTRA_CFLAGS += -D"__"$(KERNELBIT)"bit__" -Wall -DSEC_BOX_VERSION=\"V0.0.1\"
PWD = $(shell pwd)

default:
	@echo $(EXTRA_CFLAGS)
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	strip --strip-debug sec_box.ko

OBJFILE = .*.cmd *.mod.c .*.o.cmd *.o *.ko\
	  *.ko.* modules.order Module.markers Module.symvers
clean:
	rm -f $(OBJFILE)




