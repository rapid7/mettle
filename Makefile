
all: mettle

include make/Makefile.common
include make/Makefile.mettle
include make/Makefile.tools

distclean:
	@rm -fr $(BUILD)

clean:
	@rm -fr $(BUILD)/mettle

ARCHES := $(shell cat ARCHES)

# Create the individual build/clean/dist-clean rules for each arch...
define rules_for_each_arch

$(strip $(1)).build: $(ROOT)/build/tools/musl-cross/.unpacked $(ROOT)/mettle/configure
	make TARGET=$(strip $(1))

$(strip $(1)).install:
	make TARGET=$(strip $(1)) install

$(strip $(1)).clean:
	make TARGET=$(strip $(1)) clean

$(strip $(1)).distclean:
	make TARGET=$(strip $(1)) distclean

endef

$(foreach a, $(ARCHES), $(eval $(call rules_for_each_arch, $(strip $(a)))))

all-parallel: $(patsubst %,%.build,$(ARCHES))

clean-parallel: $(patsubst %,%.clean,$(ARCHES))

distclean-parallel: $(patsubst %,%.distclean,$(ARCHES))

install-parallel: $(patsubst %,%.install,$(ARCHES))
