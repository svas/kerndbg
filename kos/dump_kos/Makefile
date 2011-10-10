#linux source directory
SOURCE_DIR:=../..//linux-2.6.38.8

obj-m += shm_ko.o

all : libs

libs:
	make -C $(SOURCE_DIR) M=`pwd` modules

clean:
	make -C $(SOURCE_DIR) M=`pwd` clean
