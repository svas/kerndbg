EXE=shmget
obj-u = $(EXE).o

CC:=gcc   -g -O0

all : $(EXE)

test: $(obj-u)
	$(CC) $(CFLAGS) -o $@ $(obj-u)

clean:
	rm -f $(EXE).o $(EXE)


