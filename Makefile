all: mettle

include make/Makefile.common
include make/Makefile.mettle
include make/Makefile.tools

distclean:
	@rm -fr $(BUILD)

clean:
	@rm -fr $(BUILD)/mettle
