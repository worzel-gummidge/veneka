# veneka
veneka is a *shona*(Zimbabwe) word meaning '*illuminate*'. these two very simple scripts; veneka.py and veneka.idc are scripts that are meant to run within Immunity Debugger and IDA Pro respectively. the purpose of these scripts is to shed light on what additional functions the executable is seeking out. veneka runs the PE file under scrutiny and hooks the Kernel32 functions LoadLibraryA and GetProcAddress. once the PE file has executed to completion veneka reports all new libraries loaded by LoadLibraryA and processes that have been resolved by GetProcAddress.

the script may be useful in giving the reverser/ analyst a more complete view of the APIs/ DLLs called/ imported by the debugged process.



#### veneka.idc

veneka.idc is meant to be run as a script within IDA Pro. the script sets conditional breakpoints on GetProcAddress and LoadLibrary and monitors the APIs' parameters and return values. the script's output is displayed in the output window in IDA Pro.

####veneka.py

this is a pyCommands script to be run within Immunity Debugger. the script sets breakpoints on GetProcAddress and LoadLibrary and monitors the APIs' parameters and return values. the script's output is displayed in the log window of Immunity Debugger. place the script in the pyCommands directory in order to run successfully