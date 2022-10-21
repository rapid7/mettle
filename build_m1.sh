cp deps/config.sub mettle/config.sub
make TARGET=aarch64-apple-darwin
cd build/aarch64-apple-darwin/json-c/ && autoreconf -fiv && cd ../../..
make TARGET=aarch64-apple-darwin
cp darwin_sigar.c build/aarch64-apple-darwin/libsigar/src/os/darwin/darwin_sigar.c 
make TARGET=aarch64-apple-darwin
cd build/aarch64-apple-darwin/libdnet/ && autoreconf -fiv && cd ../../..
make TARGET=aarch64-apple-darwin
