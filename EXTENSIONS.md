Mettle Extensions
=================

Mettle now supports loadable extensions!  You simply use the Mettle `load <extension name>` command in msfconsole, and the extension is downloaded to the target and executed.  This allows functionality to be provided "on demand" when/where it's needed rather than building everything into Mettle directly.

The first extension provided is **sniffer**, which captures packets on a network interface of the target.  Feel free to reference this extension when building your own extension(s)!

What's a Mettle Extension?
--------------------------

A Mettle extension is a binary excutable, compiled for the target OS+architecture.  The Mettle `load` command (via msfconsole) will do the following:

* download the extension across the network to the target
  * extensions built as an executable or binary image are both supported
* fork it as a process on the target
  * extensions built as an executable will be written to the target's filesystem
  * extensions built as a binary image will _*not*_ be written to the target's filesystem
* enable the associated commands for the user to issue at the Mettle command prompt

That's it!

Creating an Extension
---------------------

* create a new directory for your extension source code in mettle/mettle/extensions/\<your extension name\>
  * create a new automake Makefile in this new directory (e.g. mettle/mettle/extensions/\<your extension name\>/Makefile.am
  * see mettle/mettle/extensions/sniffer/Makefile.am as an example
  * create associated source/header files for your extension (see notes below)
* add your new extension directory to the SUBDIRS variable in mettle/mettle/extensions/Makefile.am
* add your extension's Makefile to the **AC_CONFIG_FILES** macro in mettle/mettle/configure.ac 
* now you should be able to build your extension with the *make* command at the top-level mettle directory
  * the executable of your extension will appear in build/\<OS-arch-tool-etc directory\>/mettle/extensions/\<your extension name\> directory
* to test your extension, copy it (as filename **ext_server_\<your extension name\>.bin**) to appear alongside other extensions of the metasploit-payloads gem (wherever that is installed on your system)
  * e.g. I'm using rvm, and my metasploit-payloads gem is installed in ~/.rvm/gems/ruby-2.4.1@metasploit-framework/gems/metasploit-payloads-1.3.0/data/meterpreter/
* you should now be able to start up `msfconsole`, get a Mettle session, and load your new extension with the `load <your extension name>` command (well, once you have code in Framework's lib/rex/post/meterpreter/extensions/\<your extension name\> directory to work with it, anyhow)

A few things to know when creating your extension:

* make sure to `#incude <common/extension.h>`
  * contains function prototypes and other include files needed for an extension
* in your `main()` function:
  * call `extension()` to initialize and get a pointer you can use for the following steps
  * call `extension_add_handler()` to let Mettle know you are registering a handler function for a specific command
    * do this for each command your extension will be handling
  * call `extension_start()` to jump into running the event loop
    * after this call, the event loop kicks in and code will be called as TLVs with associated commands arrive
  * call `extension_free()` to gracefully close+free associated items
  
Some Details
------------

Communication between Mettle and extensions occurs over standard I/O (stdin, stdout, stderr).  When an extension first starts up, it sends the commands it accepts+handles (as strings delimited by newline characters) to Mettle via stdout, finally sending two newline characters back-to-back at the end to indicate that the full list of commands has been sent.  Mettle will associate these commands to the specifc extension, allowing for future incoming TLV requests to be directed to the proper handling code.

Once Mettle has associated an extension's commands, the stdin and stdout communications between Mettle and the extension switch over to exclusively using unencrypted TLV packets.  This allows Mettle to be the central point of all TLV en/decryption between the target and Framework endpoints, while getting the value out of reusing the known+existing TLV format and processing code.

Additionally, extensions can log error (e.g. log_error()), informational (e.g. log_info()), or debug (e.g. log_debug()) messages as plain old NULL-terminated strings to Mettle via stderr.  Currently, Mettle will treat all incoming extension messages via stderr at the "info" (2) log level.  
