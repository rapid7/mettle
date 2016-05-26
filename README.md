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

To completely reset your dev environment and delete all binary artifacts:

```
rake mettle:ultraclean
```

Gem API
-------

The gem provides one function for accessing binary payloads:
```ruby
MetasploitPayloads::Mettle.read(platform_triple, artifact)
```

The available platform triples are:
* `aarch64-linux-musl`
* `arm-linux-musleabi`
* `arm-linux-musleabihf`
* `i486-linux-musl`
* `mipsel-linux-musl`
* `mips-linux-musl`
* `mipsel-linux-muslsf`
* `mips-linux-muslsf`
* `powerpc-linux-musl`
* `powerpc-linux-muslsf`
* `x86_64-linux-musl`

The available artifacts are:
* `mettle` - a standalone executable that take command-line arguments (see `mettle -h`)
* `mettle.bin` - a process image that must be started with a custom stack (see `doc/stack_requirements.md`)


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
