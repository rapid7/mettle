#ARCH=i386
#TARGET:=i386-linux-eng
TARGET:=native

all: tools mettle

include scripts/make/Makefile.common
include scripts/make/Makefile.libpcap
include scripts/make/Makefile.libressl
include scripts/make/Makefile.libtlv
include scripts/make/Makefile.libuv
include scripts/make/Makefile.kernel-headers
include scripts/make/Makefile.mettle
include scripts/make/Makefile.tools

distclean:
	@rm -fr $(BUILD)
	@rm -fr tools

clean:
	@rm -fr $(BUILD)/mettle
