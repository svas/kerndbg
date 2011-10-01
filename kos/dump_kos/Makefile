#linux source directory
SOURCE_DIR:=/home/sree-virt/dev_mmap/linux/

obj-m += shm_ko.o

all : libs

libs:
	make -C $(SOURCE_DIR) M=`pwd` modules

clean:
	make -C $(SOURCE_DIR) M=`pwd` clean
