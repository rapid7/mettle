Mettle
======

This is an implementation of a native-code Meterpreter, designed for
portability, embeddability, and low resource utilization. It can run on the
smallest embedded Linux targets to big iron, and targets Android, iOS, macOS,
Linux, and Windows, but can be ported to almost any POSIX-compliant
environment.

Building on Linux
------------

Debain, Ubuntu, and derivatives are most supported for builds. To build, you need at least 5GB of free disk space, and the following packages available:

```
# Dependencies
apt install curl build-essential git autoconf automake libtool bison flex gcc ruby rake bundler git mingw-w64
```

The Dockerfile under docker/Dockerfile contains a pre-configured build
environment as well.

Building on macOS
------------

On macOS you will need the following:

```
# Install brew (if you have not already)
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

# Install command line tools
xcode-select --install

# Dependencies
brew install coreutils m4 automake mingw-w64 libtool
```

Make Targets
------------

For general development, there are a few make targets defined:

Running `make` will build for the local environment. E.g. if you're on macOS,
it will build for macOS using your native compiler and tools.

`make TARGET=triple` will build for a specific host triple. See below for some
common ones.

`make clean` will clean the 'mettle' directory for the current build target

`make distclean` will clean the entire build target`

`make all-parallel` will build for every known target, useful with '-j' to build multiple targets at once.

`make clean-parallel` and `make distclean-parallel` do similar for all targets.

Packaging
=========

To build the gem for distribution (currently requires Linux or macOS):

```
rake build
```

To check the resulting binaries:

```
rake check
```

To completely reset your dev environment and delete all binary artifacts:

```
rake mettle:ultraclean
```

Gem API
-------

To generate a payload with Mettle:
```ruby
mettle = MetasploitPayloads::Mettle.new(platform_triple, config={})
```

The available platform triples for Linux targets are:

* `aarch64-linux-musl`
* `armv5l-linux-musleabi`
* `armv5b-linux-musleabi`
* `i486-linux-musl`
* `x86_64-linux-musl`
* `powerpc-linux-muslsf`
* `powerpc64le-linux-musl`
* `mips-linux-muslsf`
* `mipsel-linux-muslsf`
* `mips64-linux-muslsf`
* `s390x-linux-musl`

For Mingw32-64 Windows targets, the following triples are added. On up-to-date
Debian / Ubuntu systems, the `mingw-w64` package will install both toolchains.

* `x86_64-w64-mingw32`
* `i686-w64-mingw32`

For macOS/iOS builds, the following triples are added. To target older macOS/OSX
versions, see https://github.com/phracker/MacOSX-SDKs to get the appropriate
SDK folder.

* `arm-iphone-darwin`
* `aarch64-iphone-darwin`
* `i386-apple-darwin`
* `x86_64-apple-darwin`

Available config options are:
* `:background` - fork to background as a daemon
* `:debug` - to turn on debug messages
* `:log_file` - the file to send debug messages to instead of `stderr`
* `:uri` - the uri to connect back to
* `:uuid` - the UUID to identify the payload

Config options can also be set with:
```ruby
mettle.config[:key] = val
```

To get a binary with installed options call:
```ruby
mettle.to_binary(format=:process_image)
```

The formats are:
* `:exec` - a standalone executable that can take command-line arguments (see `mettle -h`) or use pre-set ones
* `:process_image` - a process image that must be started with a custom stack (see `doc/stack_requirements.md`)


Using with Metasploit
---------------------

To pull your local changes of mettle into your Metasploit install:

1. Add `-dev` to the version in `lib/metasploit_payloads/mettle/version.rb`
2. Build the gem as above
3. Copy `pkg/metasploit-payloads-mettle-X.X.X.pre.dev.gem` to the box you are using for Metasploit if it is different
4. Change the version in your metasploit-framework.gemspec to match the one you just built
5. `gem install <path to new gem>` (for example: 'metasploit_payloads-mettle', '0.4.1.pre.dev')
6. Run `bundle install` in your Framework directory, and ensure you see something like `Using metasploit_payloads-mettle 0.4.1.pre.dev (was 0.4.1)` in the output
7. Congrats, you are now done!

Pushing out a New Gem
----------------------
Right now, only Rapid7 Employees can push out a new Gem.
1. Test Locally
2. Check out the version file again to return it to the original state
3. Increment the version
4. Land the changes to upstream master
5. Kick off the Jenkins Payload task Payloads-Mettle-Build-MacOS-Artifacts (must be logged in to the R7 build infrastructure)
6. Monitor for the new gem on rubygems.org
7. Once the gem appears, make a PR for bumping the version in framework

