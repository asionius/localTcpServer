rm ./lib/*.so
make clean -C client
make clean -C server
make clean -C network
make -C network
make -C client
make -C server
