LUA EXTENSION
=================

This loadable extension allows users to execute lua code on the target's computer, it was made for education purposes and might not be complete.

Loading Lua
-------------------

Once you've established a connection to Mettle, you can load the lua extension with the following command in your msfconsole terminal:

`load lua`

If things go according to plan, you should get a message that the extension was successfully loaded:

```
meterpreter > load lua
Loading extension lua...Success.
```

Using Lua
-----------------

The lua extension is pretty bare bones thus you can execute code but not get its returns value.

```
Lua Commands
============

    Command       Description
    -------       -----------
    lua_dostring  Execute provided string
```

An Example
-----------------

Executing non valid code:
```
meterpreter > lua_dostring "msf"
[-] lua_dostring: Operation failed: 1
```

Executing valid code:
```
meterpreter > lua_dostring "msf = 1"
meterpreter > 
```
