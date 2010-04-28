ifndef TOLAPAI_ROOT
$(error TOLAPAI_ROOT is undefined. Please set the path \
	"-> setenv TOLAPAI_ROOT <path to split driver source>")
endif

ifndef KERNEL_SOURCE_ROOT
$(error KERNEL_SOURCE_ROOT is undefined. Please set the path \
	"-> setenv KERNEL_SOURCE_ROOT <path to kernel source>")
endif

ifndef TOLAPAI_BUILD_OUTPUT
$(error TOLAPAI_BUILD_OUTPUT is undefined. Please set the path \
	"-> setenv TOLAPAI_BUILD_OUTPUT <path to output dir >")
endif


ifneq ($(KERNELRELEASE),)

obj-m := ixpback.o
module-objs := ixpback-pagemap.o ixpback.o
EXTRA_CFLAGS :=	-I$(TOLAPAI_ROOT)/common/include -I$(TOLAPAI_ROOT)/backend/include

else
 
all:
	test -d $(TOLAPAI_BUILD_OUTPUT)/backend || mkdir -p $(TOLAPAI_BUILD_OUTPUT)/backend;
	$(MAKE) -C $(KERNEL_SOURCE_ROOT) M=$(PWD) modules
	@echo 'Copying Outputs';\
	mv -f *.o $(TOLAPAI_BUILD_OUTPUT)/backend;\
        mv -f *.ko $(TOLAPAI_BUILD_OUTPUT)/backend;
	cp xenstore_setup.sh $(TOLAPAI_BUILD_OUTPUT)/backend/;
clean:
	rm -rf $(TOLAPAI_BUILD_OUTPUT)/backend/ixpback*.*\
 	rm $(TOLAPAI_BUILD_OUTPUT)/backend/xenstore_setup.sh;
	$(MAKE) -C $(KERNEL_SOURCE_ROOT) M=$(PWD) clean
	
endif

