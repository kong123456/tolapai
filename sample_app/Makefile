ifndef KERNEL_SOURCE_ROOT
$(error KERNEL_SOURCE_ROOT is undefined. Please set the path \
	"-> setenv KERNEL_SOURCE_ROOT <path to kernel source>")
endif

ifneq ($(KERNELRELEASE),)

obj-m := cpa_cipher_perf.o
module-objs := cpa_cipher_perf.o

else
 
all:
	$(MAKE) -C $(KERNEL_SOURCE_ROOT) M=$(PWD) modules
	
clean:
	$(MAKE) -C $(KERNEL_SOURCE_ROOT) M=$(PWD) clean
	
endif

