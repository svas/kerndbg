EXE=shmget
obj-u = $(EXE).o

CC:=gcc -g -O0
LDFLAGS:=-lcurses

all : $(EXE)

test: $(obj-u)
	$(CC) $(CFLAGS) -o $@ $(obj-u) $(LDFLAGS)

clean:
	rm -f $(EXE).o $(EXE)


