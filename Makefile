KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
MDIR := klogger


.PHONY: modules modules_install modules_clean
all: modules
install: modules_install
clean: modules_clean

modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

modules_install: modules
	$(MAKE) INSTALL_MOD_PATH=$(DESTDIR) INSTALL_MOD_DIR=$(MDIR) -C $(KDIR) M=$(CURDIR) modules_install

modules_clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

