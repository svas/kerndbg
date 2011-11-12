#linux source directory
SOURCE_DIR:=/mnt/hgfs/prj/shm_prj_git/linux-2.6.38.8

obj-m += lkgdb.o

all : libs

libs:
	make -C $(SOURCE_DIR) M=`pwd` modules

clean:
	make -C $(SOURCE_DIR) M=`pwd` clean
