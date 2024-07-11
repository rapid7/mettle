Mettle Extensions
=================

Mettle now supports loadable extensions!  You simply use the Mettle `load <extension name>` command in msfconsole, and the extension is downloaded to the target and executed.  This allows functionality to be provided "on demand" when/where it's needed rather than building everything into Mettle directly.

The first extension provided is **sniffer**, which captures packets on a network interface of the target.  Feel free to reference this extension when building your own extension(s)!

What's a Mettle Extension?
--------------------------

A Mettle extension is a binary executable or image, compiled for the target OS+architecture.  The Mettle `load` command (via msfconsole) will do the following:

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
  * the executable of your extension will appear in build/\<OS-arch-tool-etc directory\>/bin directory
* to test your extension, copy it to appear alongside other extensions of the metasploit_payloads-mettle gem's build/\<OS-arch-tool-etc directory\>/bin/ directory (wherever that is installed on your system)
  * e.g. I'm using rvm, and my metasploit_payloads-mettle gem has its extension installed in ~/.rvm/gems/ruby-2.4.2@metasploit-framework/gems/metasploit-payloads-0.3.2/build/\<OS-arch-tool-etc directory\>/bin/
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

Communication between Mettle and extensions occurs over standard I/O (stdin, stdout, stderr).  Once Mettle has started the extension subprocess, it will forward the CORE_LOADLIB command to the extension process. The extension process then replies to it with the result and command IDs that it supports. The parent Mettle process watches for the response to this CORE_LOADLIB command and will associate these commands to the specifc extension, allowing for future incoming TLV requests to be directed to the proper handling code.

The stdin and stdout communications between Mettle and the extension process exclusively use unencrypted TLV packets.  This allows Mettle to be the central point of all TLV en/decryption between the target and Framework endpoints, while getting the value out of reusing the known+existing TLV format and processing code.

Additionally, extensions can log error (e.g. log_error()), informational (e.g. log_info()), or debug (e.g. log_debug()) messages as plain old NULL-terminated strings to Mettle via stderr.  Currently, Mettle will treat all incoming extension messages via stderr at the "info" (2) log level.  
