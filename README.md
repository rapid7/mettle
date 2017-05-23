Mettle
======

**This repo has submodules!** Remember to run
```
git submodule init; git submodule update
```
after cloning.

To build the gem (currently requires Linux or macOS):

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

OSX requirements
------------

On OSX you will need the following:
```
# Install brew (if you have not already)
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

# Install command line tools
xcode-select --install

# Dependencies
brew install coreutils m4 automake
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

For macOS/iOS builds, the following triples are added. To target older MacOSX
versions, see https://github.com/phracker/MacOSX-SDKs to get the appropriate
SDK folder.

* `arm-iphone-darwin`
* `aarch64-iphone-darwin`
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

1. Add `-dev` to the version in `lib/metasploit-payloads/mettle/version.rb`
2. Build the gem as above
3. Copy `pkg/metasploit-payloads-mettle-X.X.X.pre.dev.gem` to the box you are using for Metasploit if it is different
4. Change the version in your metasploit-framework.gemspec to match the one you just build
5. `gem install <path to new gem>`
6. Run `bundle install` in your Framework directory
7. Congrats, you are now done!
