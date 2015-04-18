all: tools mettle

include scripts/make/Makefile.common
include scripts/make/Makefile.libpcap
include scripts/make/Makefile.libressl
include scripts/make/Makefile.libtlv
include scripts/make/Makefile.json-c
include scripts/make/Makefile.libuv
include scripts/make/Makefile.kernel-headers
include scripts/make/Makefile.mettle
include scripts/make/Makefile.tools

distclean:
	@rm -fr $(BUILD)

clean:
	@rm -fr $(BUILD)/mettle
