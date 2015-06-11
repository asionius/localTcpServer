#all:../lib/network.so

PROJECT=libnetwork.so
PREFIX=../lib
MYLIB=
SYSLIB= -lpthread -lrt
CFLAGS=-g -O2 -I../include -shared -fPIC
#CFLAGS+= -Wall
CC=gcc
GCC=gcc
OBJDIR=../lib
SRCS=$(wildcard *.cpp) $(wildcard *.c)
OBJS=$(patsubst %.c,%.o,$(SRCS))

$(PROJECT):$(OBJS)
	$(GCC) -o $@ $^ $(CFLAGS) $(SYSLIB) $(MYLIB)
	cp -f $(PROJECT) $(PREFIX)
	cp -f *.h ../include

%.o:%.cpp %.c
	$(GCC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f *.o $(PROJECT) 
