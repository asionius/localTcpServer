#编译出client程序,作为客户进程的模拟

PROJECT=client
PREFIX=../bin
INCLUDE=-I../include -I../network
CFLAGS=-Wall -g -O2 -Wl,-rpath=../lib $(INCLUDE)
MYLIB=-L./ -L../lib -lnetwork
VPATH+=../lib
SYSLIB= -pthread
SUBSYSTEM=network
SUBDIR=../network
CC=gcc
GCC=gcc
OBJDIR=../lib
#SRCS=$(wildcard *.cpp) $(wildcard *.c)
SRCS=client.c
OBJS=$(patsubst %.c,%.o,$(SRCS))

$(PROJECT):$(OBJS)
	$(GCC) -o $@ $^ $(CFLAGS) $(INCLUDE) $(SYSLIB) $(MYLIB)
	cp -f $(PROJECT) $(PREFIX)	 
	cp -f *.h ../include

$(OBJDIR)/%.o:%.cpp %.c
	$(GCC) -c -o $@ $< $(CFLAGS) $(INCLUDE)

clean:
	rm -f *.o $(PROJECT)

