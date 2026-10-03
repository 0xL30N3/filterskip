obj-m += filterd.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# PROC_MODE=1 switches from port-based to process-based access control
ifdef PROC_MODE
  ccflags-y += -DDAWG_PROC_FILTER
endif

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
