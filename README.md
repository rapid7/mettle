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
