all: mettle

include make/Makefile.common
include make/Makefile.curl
include make/Makefile.libdnet
include make/Makefile.libpcap
include make/Makefile.libsigar
include make/Makefile.json-c
include make/Makefile.libuv
include make/Makefile.mbedtls
include make/Makefile.mettle
include make/Makefile.tools

distclean:
	@rm -fr $(BUILD)

clean:
	@rm -fr $(BUILD)/mettle
