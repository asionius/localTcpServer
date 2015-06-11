PROJECT=server
PREFIX=../bin
INCLUDE=-I../include -I../network 
CFLAGS= -g -O2 -Wl,-rpath=../lib
#CFLAGS=-Wall -g -O2 -Wl,-rpath=../lib
MYLIB=-L./ -L../lib -lnetwork 
VPATH+=../lib
SYSLIB= -pthread
SUBSYSTEM=network
SUBDIR=../network
CC=gcc
GCC=gcc
OBJDIR=../lib
SRCS=$(wildcard *.cpp) $(wildcard *.c)
OBJS=$(patsubst %.c,%.o,$(SRCS))

#all:$(SUBSYSTEM) $(PROJECT)

#$(SUBSYSTEM):
#	$(MAKE) -C $(SUBDIR)

$(PROJECT):$(OBJS)
	$(GCC) -o $@ $^ $(CFLAGS) $(INCLUDE) $(SYSLIB) $(MYLIB)
	cp -f $(PROJECT) $(PREFIX)	 
	cp -f *.h ../include

%.o:%.c
	$(GCC) -c -o $@ $< $(CFLAGS) $(INCLUDE)

clean:
	rm -f *.o $(PROJECT)
#	$(MAKE) clean -C $(SUBDIR)

