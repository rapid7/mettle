PROJECT_NAME:=mettle

ARCH=i386
TARGET:=i386-linux-eng

include scripts/make/Makefile.common
include scripts/make/Makefile.libev
include scripts/make/Makefile.libpcap
include scripts/make/Makefile.libressl
include scripts/make/Makefile.libtlv
include scripts/make/Makefile.kernel-headers
include scripts/make/Makefile.tools

$(BUILD)/$(PROJECT_NAME).bin: libev libpcap
	@mkdir -p $(BUILD)
	@touch $(BUILD)/$(PROJECT_NAME).bin

distclean:
	@rm -fr $(BUILDS)
	@rm -fr tools

clean:
	@rm -fr $(BUILD)
