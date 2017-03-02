
all: mettle

include make/Makefile.common
include make/Makefile.mettle
include make/Makefile.tools

distclean:
	@rm -fr $(BUILD)

clean:
	@rm -fr $(BUILD)/mettle

all-parallel: \
	i686-w64-mingw32.build \
	x86_64-linux-musl.build \
	i486-linux-musl.build \
	aarch64-linux-musl.build \
	armv5l-linux-musleabi.build \
	armv5b-linux-musleabi.build \
	powerpc-linux-muslsf.build \
	powerpc64le-linux-musl.build \
	mips-linux-muslsf.build \
	mipsel-linux-muslsf.build \
	mips64-linux-muslsf.build \
	s390x-linux-musl.build

clean-parallel: \
	i686-w64-mingw32.clean \
	x86_64-linux-musl.clean \
	i486-linux-musl.clean \
	aarch64-linux-musl.clean \
	armv5l-linux-musleabi.clean \
	armv5b-linux-musleabi.clean \
	powerpc-linux-muslsf.clean \
	powerpc64le-linux-musl.clean \
	mips-linux-muslsf.clean \
	mipsel-linux-muslsf.clean \
	mips64-linux-muslsf.clean \
	s390x-linux-musl.clean

distclean-parallel: \
	i686-w64-mingw32.distclean \
	x86_64-linux-musl.distclean \
	i486-linux-musl.distclean \
	aarch64-linux-musl.distclean \
	armv5l-linux-musleabi.distclean \
	armv5b-linux-musleabi.distclean \
	powerpc-linux-muslsf.distclean \
	powerpc64le-linux-musl.distclean \
	mips-linux-muslsf.distclean \
	mipsel-linux-muslsf.distclean \
	mips64-linux-muslsf.distclean \
	s390x-linux-musl.distclean

i686-w64-mingw32.build: $(ROOT)/build/tools/musl-cross/.unpacked
	make TARGET=i686-w64-mingw32
i686-w64-mingw32.clean:
	make TARGET=i686-w64-mingw32 clean
i686-w64-mingw32.distclean:
	make TARGET=i686-w64-mingw32 distclean
x86_64-linux-musl.build: $(ROOT)/build/tools/musl-cross/.unpacked
	make TARGET=x86_64-linux-musl
x86_64-linux-musl.clean:
	make TARGET=x86_64-linux-musl clean
x86_64-linux-musl.distclean:
	make TARGET=x86_64-linux-musl distclean
i486-linux-musl.build: $(ROOT)/build/tools/musl-cross/.unpacked
	make TARGET=i486-linux-musl
i486-linux-musl.clean:
	make TARGET=i486-linux-musl clean
i486-linux-musl.distclean:
	make TARGET=i486-linux-musl distclean
aarch64-linux-musl.build: $(ROOT)/build/tools/musl-cross/.unpacked
	make TARGET=aarch64-linux-musl
aarch64-linux-musl.clean:
	make TARGET=aarch64-linux-musl clean
aarch64-linux-musl.distclean:
	make TARGET=aarch64-linux-musl distclean
armv5l-linux-musleabi.build: $(ROOT)/build/tools/musl-cross/.unpacked
	make TARGET=armv5l-linux-musleabi
armv5l-linux-musleabi.clean:
	make TARGET=armv5l-linux-musleabi clean
armv5l-linux-musleabi.distclean:
	make TARGET=armv5l-linux-musleabi distclean
armv5b-linux-musleabi.build: $(ROOT)/build/tools/musl-cross/.unpacked
	make TARGET=armv5b-linux-musleabi
armv5b-linux-musleabi.clean:
	make TARGET=armv5b-linux-musleabi clean
armv5b-linux-musleabi.distclean:
	make TARGET=armv5b-linux-musleabi distclean
powerpc-linux-muslsf.build: $(ROOT)/build/tools/musl-cross/.unpacked
	make TARGET=powerpc-linux-muslsf
powerpc-linux-muslsf.clean:
	make TARGET=powerpc-linux-muslsf clean
powerpc-linux-muslsf.distclean:
	make TARGET=powerpc-linux-muslsf distclean
powerpc64le-linux-musl.build: $(ROOT)/build/tools/musl-cross/.unpacked
	make TARGET=powerpc64le-linux-musl
powerpc64le-linux-musl.clean:
	make TARGET=powerpc64le-linux-musl clean
powerpc64le-linux-musl.distclean:
	make TARGET=powerpc64le-linux-musl distclean
mips-linux-muslsf.build: $(ROOT)/build/tools/musl-cross/.unpacked
	make TARGET=mips-linux-muslsf
mips-linux-muslsf.clean:
	make TARGET=mips-linux-muslsf clean
mips-linux-muslsf.distclean:
	make TARGET=mips-linux-muslsf distclean
mipsel-linux-muslsf.build: $(ROOT)/build/tools/musl-cross/.unpacked
	make TARGET=mipsel-linux-muslsf
mipsel-linux-muslsf.clean:
	make TARGET=mipsel-linux-muslsf clean
mipsel-linux-muslsf.distclean:
	make TARGET=mipsel-linux-muslsf distclean
mips64-linux-muslsf.build: $(ROOT)/build/tools/musl-cross/.unpacked
	make TARGET=mips64-linux-muslsf
mips64-linux-muslsf.clean:
	make TARGET=mips64-linux-muslsf clean
mips64-linux-muslsf.distclean:
	make TARGET=mips64-linux-muslsf distclean
s390x-linux-musl.build: $(ROOT)/build/tools/musl-cross/.unpacked
	make TARGET=s390x-linux-musl
s390x-linux-musl.clean:
	make TARGET=s390x-linux-musl clean
s390x-linux-musl.distclean:
	make TARGET=s390x-linux-musl distclean
