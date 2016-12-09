Mettle
======

**This repo has submodules!** Remember to run
```
git submodule init; git submodule update
```
after cloning.

To build the gem (currently requires linux):

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

The available platform triples are:
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

Available config options are:
* `:uri` - the uri to connect back to
* `:uuid` - the UUID to identify the payload
* `:debug` - to turn on debug messages
* `:log_file` - the file to send debug messages to instead of `stderr`

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
