#!/usr/bin/env python

arches = file('ARCHES').read().splitlines()
makefile = open('Makefile', 'w')

makefile.write("""
all: mettle

include make/Makefile.common
include make/Makefile.mettle
include make/Makefile.tools

distclean:
\t@rm -fr $(BUILD)

clean:
\t@rm -fr $(BUILD)/mettle

""")

makefile.write("all-parallel: \\\n")
makefile.write(" \\\n".join(["\t%s.build" % a for a in arches]))
makefile.write("\n\n")

makefile.write("clean-parallel: \\\n")
makefile.write(" \\\n".join(["\t%s.clean" % a for a in arches]))
makefile.write("\n\n")

makefile.write("distclean-parallel: \\\n")
makefile.write(" \\\n".join(["\t%s.distclean" % a for a in arches]))
makefile.write("\n\n")

for arch in arches:
    makefile.write("%s.build: $(ROOT)/build/tools/musl-cross/.unpacked\n" % arch)
    makefile.write("\tmake TARGET=%s\n" % arch)
    makefile.write("%s.clean:\n" % arch)
    makefile.write("\tmake TARGET=%s clean\n" % arch)
    makefile.write("%s.distclean:\n" % arch)
    makefile.write("\tmake TARGET=%s distclean\n" % arch)

makefile.close()
