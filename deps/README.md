# Source packages Mettle Dependencies

## Build Tools

Mettle includes a few build tools that are used generically across all build
targets. These tools are used for configuring some of mettle's dependencies as
well as mettle itself. The first time that you build mettle, it will compile
these tools. While these tools are also available in many OS distributions,
including the correct versions here makes it easier to build mettle when they
are unavailable or are old versions, such as when targeting legacy Unix systems
like Solaris and HP-UX.

 - [autoconf](https://ftp.gnu.org/gnu/autoconf/), used for cross-compilation of packages and mettle itself

 - [libtool](https://www.gnu.org/software/libtool/), used for portable library generation (also autoconf/automake)

 - [automake](https://www.gnu.org/software/automake/), makes dealing with autoconf easier

 - [bison](https://www.gnu.org/software/bison/), parser generator, used by libpcap

 - [flex](https://github.com/westes/flex), lexer generator, used with bison for libpcap

 - config.guess / config.sub, scripts used for supporting new OSes and CPUs
   with autoconf. Because autoconf itself hasn't seen a release since 2012 (at
   the time of this writing), it only supports whatever OSes and CPUs were
   released at that time. Grabbing the latest development versions adds support
   for newer OSes and CPUs. See config.update.sh for download details.

 - [coreutils](https://www.gnu.org/software/coreutils/), GNU core utilities, these are here to help building on old platforms like Solaris where the system tools are odd or old. These are only built if needed.

 - [m4](https://www.gnu.org/software/m4/), GNU m4, this is used by autoconf/automake, and only is built if the system version of m4 is too old to work properly, such as on Solaris.

## Libraries

These libraries are built for each build target.

 - [libpcap](https://www.tcpdump.org/), used for network packet capture. The library can also capture many other packet types, such as bluetooth and usb.

 - [json-c](https://github.com/json-c/json-c), JSON parsing and generation library

 - [libz](https://sortix.org/libz/), the Sortix libz fork, which supports more standard C code and removes some unsafe code.

 - [mbedtls](https://tls.mbed.org/), a small and portable TLS and crypto library

 - [curl](https://curl.haxx.se/download.html), a swiss-army knife network transfer library, supporting many different network protocols

Forked libraries from upstream. These either have an inactive upstream, or it's not clear how to get fixes reincorporated.

 - [libev](http://software.schmorp.de/pkg/libev.html), a fast and portable event loop, similar to libevent and libuv. [fork](https://github.com/busterb/libev).

 - [libeio](http://software.schmorp.de/pkg/libeio.html), an I/O library that works with libev to provide file, socket, and other Posix API primitives. [fork](https://github.com/busterb/libeio)

 - [SIGAR](https://github.com/hyperic/sigar), 'System Information Gaterer And Reporter', OS-independent interfaces for getting system info [fork](https://github.com/busterb/sigar)

 - [libdnet](http://libdnet.sourceforge.net/), provides low-level network packet generation and parsing, as well as network configuration manipulation tools. [fork](https://github.com/busterb/libdnet)
