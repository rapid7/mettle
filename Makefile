all: mettle

include Makefile.common
include Makefile.curl
include Makefile.libdnet
include Makefile.libpcap
include Makefile.libsigar
include Makefile.json-c
include Makefile.libuv
include Makefile.kernel-headers
include Makefile.mbedtls
include Makefile.mettle
include Makefile.tools

distclean:
	@rm -fr $(BUILD)

clean:
	@rm -fr $(BUILD)/mettle
