#!/bin/bash
CONNECT_NUM=$1
echo "connect num is $CONNECT_NUM"
echo "ulimit -n $CONNECT_NUM"

ulimit -u 10000
ulimit -n $CONNECT_NUM
ulimit -d unlimited
ulimit -m unlimited
ulimit -s unlimited
ulimit -t unlimited
ulimit -v unlimited
./server
