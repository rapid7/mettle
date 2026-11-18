
all: mettle

include make/Makefile.tools
include make/Makefile.common
include make/Makefile.mettle

DOCKER_CONTAINER=rapid7/build:mettle
DOCKER_TARGET ?= x86_64-linux-musl

# Build mettle inside the official build container (no local toolchain or
# autotools required). Override the arch with DOCKER_TARGET=<triple>. Only the
# mettle checkout is mounted; build artifacts are chowned back to the invoking
# user. Output lands in build/$(DOCKER_TARGET)/bin/{mettle,mettle.bin}.
docker:
	docker run --rm -v "$(CURDIR)":/mettle -w /mettle $(DOCKER_CONTAINER) \
		bash -c "make TARGET=$(DOCKER_TARGET); rc=$$?; chown -R $(shell id -u):$(shell id -g) /mettle; exit $$rc"

distclean:
	@rm -fr $(BUILD)

clean:
	@rm -fr $(BUILD)/mettle

ARCHES := $(shell cat ARCHES)

# Create the individual build/clean/dist-clean rules for each arch...
define rules_for_each_arch

$(strip $(1)).build: $(TOOLS)/musl-cross/.unpacked $(if $(findstring riscv64,$(strip $(1))),$(TOOLS)/musl-cross/.riscv64-unpacked) $(if $(findstring loongarch64,$(strip $(1))),$(TOOLS)/musl-cross/.loongarch64-unpacked) $(ROOT)/mettle/configure
	make TARGET=$(strip $(1))

$(strip $(1)).install:
	make TARGET=$(strip $(1)) install

$(strip $(1)).clean:
	make TARGET=$(strip $(1)) clean

$(strip $(1)).distclean:
	make TARGET=$(strip $(1)) distclean

endef

$(foreach a, $(ARCHES), $(eval $(call rules_for_each_arch, $(strip $(a)))))

all-parallel: $(TOOLS) $(patsubst %,%.build,$(ARCHES))

clean-parallel: $(patsubst %,%.clean,$(ARCHES))

distclean-parallel: $(patsubst %,%.distclean,$(ARCHES))

install-parallel: $(patsubst %,%.install,$(ARCHES))
