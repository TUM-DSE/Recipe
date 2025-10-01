#!/bin/env sh


cd cityhash && make && sudo make install && cd ..
cd fmt/build && make && sudo make install && cd ../../
cd openssl && make -f Makefile_openssl1 && cd ../
sudo apt-get install libevent-dev libnuma-dev libgflags-dev libgoogle-glog-dev libboost-dev | echo 'Y'
cd SCONE_deps/double-conversion/build && make && sudo make install && cd ../../../
#cd folly/_build && make && cd ../../../
sudo cp /usr/local/lib/lib* /usr/lib/x86_64-linux-gnu/
