WinValgrind
===========

WinValgrind ( valgrind for windows ) : Resource leak tracking tool for windows.

Being a linux programmer, we often feel the need of the powerful memory leak detection tool similar to Valgrind on Windows environment also.

WinValgrind? is a resource leak tracking tool which will offer complete detection of Handle leaks, GDI objects leak & Memory leaks, with a simple to use command line user interface.

WinValgrind? takes inspiration from Valgrind and enables the user to track down memory issues without changing a single line of code.


How to build
=============
Before building the tool you need to have some prerequisite on your computer.

Visual studio 2k10 to latest... ( I have built in vs 2k12).
Debugging tools for windows.
SVN client like tortoisesvn.
To build the tool from source, check out the source in some local directory. Open WinValgrind?.sln and hit build solution.. Now you are ready to go :)

In the output folder you will get:

  1.) WinValgrind?.exe --> command line interface utility to inject the parasite into a process.
  
  2.) parasite.dll --> Spy DLL which hook the windows API's.

-->Enable logging for the tool by setting the value of "WINVAL_LOG" environment variable as 1.

How to use the tool
===================

Note : Tool is currently at initial stage of development, therefore I have yet not decided whether to go with the GUI.

Tool is very simple to use, just follow the below steps to get started..

Execute winvalgrind.exe on windows command prompt to see all command line options.

usage: winvalgrind [-gc] | [-sm <PID>]

        -gc     Generate the config file template.
        -sm     start monitoring the process.

1.) First you need to generate the default config.xml template.

  --> Execute "winvalgrind.exe -gc"
  
    ----> This command will generate the default config.xml file into the winvalgrind.exe directory.
      *------------ Config.xml default template-------------------*
      
      <?xml version="1.0"?>
      <WinValgrind>
              <!-- Type of HOOK -->
              <MonitorType>MEMORY</MonitorType>
              <!-- PDB Path -->
              <PDBInfo>
                      <!-- Do not remove PDB path 1 & 2 -->
                      <PDBInfo1 path="C:\Users\win-valgrind\WinValgrind\Debug\" />
                      <PDBInfo2 path="C:\Windows\system32" />
                      <!-- microsoft sysmbol server -->
                      <PDBInfo3 path="SRV*c:\Windows\Symbols*http://msdl.microsoft.com/download/symbols" />
                      <!-- Add Monitored process symbol path -->
              </PDBInfo>
      </WinValgrind>

  --> Config.xml, serves as configuration file which will be read/loaded to set the initialisation parameters for parasite.dll.
    
    --> MonitorType tag's value define type of tracing user want to enable.
    
    -----> MEMORY : Memory leak detection.
    
    -----> GDI : GDI object leak detection.
    
    -----> HANDLE: Handle leak detection.

  --> PDBInfo tags define the path to the symbol file.
    
    ----> 1st pdbinfo is the path to the directory of parasite.dll.
    
    ----> 2nd is the system DLL path.

  Note: path 1 & 2 are compulsory, do not remove them.
  
    ----> 3rd is the Microsoft symbol server path, which is optional.

2.) Edit the generated config.xml.

  --> Set the monitor type.
  Note: Currently only "HANDLE" & "MEMORY" type monitor is supported.
  
  --> Add the symbol path of the application you want to monitor.

3.) Start the application you want to monitor.

4.) Execute "winvalgrind.exe -sm <PID of the process to be monitored>".

    Once the monitoring starts you will see below internal command line which you can use to control the application.
    
    --------------------------------------
    Monitoring started for pid <PID>
    
    Command options
    
    -d  Dump the leak trace.
    -c  Clear leaks.
    -e  Exit.
    
    > 
    
    ---------------------------------------

Internals of tool
=================

Basically this application works by hooking all the windows API's which are used to allocate and deallocate memory.

Now, after the hooking is complete, For each allocation of memory I save its stack in stl map address keys. Map entry for a address is only cleared if, respective deallocation function is called on that address.

at-last, all the remaining entries in map are treated as leaked once, and there stack is dumped to file.


Currently supported API hooks
=============================

    Handle allocation APIs          Memory allocation APIs
            
    LoadLibraryA                    HeapAlloc
    LoadLibraryW                    HeapFree
    LoadLibraryExA                  HeapReAlloc
    LoadLibraryExW                  VirtualAlloc
    GetProcAddress                  VirtualFree
    CreateEventA                    VirtualAllocEx
    CreateEventW                    VirtualFreeEx
    CreateEventExA                  GlobalAlloc
    CreateEventExW                  GlobalReAlloc
    OpenEventA                      GlobalFree
    OpenEventW                      LocalAlloc
    CreateMutexA                    LocalReAlloc
    CreateMutexW                    LocalFree
    CreateMutexExA                  MapViewOfFile
    CreateMutexExW                  MapViewOfFileEx
    OpenMutexA                      UnmapViewOfFile
    OpenMutexW                      CoTaskMemAlloc
    CreateSemaphoreA                CoTaskMemRealloc
    CreateSemaphoreW                CoTaskMemFree
    CreateSemaphoreExA      
    CreateSemaphoreExW      
    OpenSemaphoreA  
    OpenSemaphoreW  
    CreateWaitableTimerA    
    CreateWaitableTimerW    
    CreateWaitableTimerExA  
    CreateWaitableTimerExW  
    OpenWaitableTimerA      
    OpenWaitableTimerW      
    CreateFileA     
    CreateFileW     
    CreateFileTransactedA   
    CreateFileTransactedW   
    FindFirstFileA  
    FindFirstFileW  
    FindFirstFileExA        
    FindFirstFileExW        
    FindFirstFileExW        
    FindFirstFileNameW      
    FindFirstFileTransactedA        
    FindFirstFileTransactedW        
    FindFirstStreamTransactedW      
    FindFirstStreamW        
    FindClose       
    OpenFileById    
    ReOpenFile      
    CreateIoCompletionPort  
    CreateRestrictedToken   
    DuplicateToken  
    DuplicateTokenEx        
    OpenProcessToken        
    OpenThreadToken 
    FindFirstChangeNotificationA    
    FindFirstChangeNotificationW    
    FindCloseChangeNotification     
    CreateMemoryResourceNotification        
    CreateFileMappingA      
    CreateFileMappingW      
    CreateFileMappingNumaA  
    CreateFileMappingNumaW  
    OpenFileMappingA        
    OpenFileMappingW        
    HeapCreate      
    HeapDestroy     
    GlobalAlloc     
    GlobalReAlloc   
    GlobalFree      
    LocalAlloc      
    LocalReAlloc    
    LocalFree       
    CreateProcessA  
    CreateProcessW  
    CreateProcessAsUserA    
    CreateProcessAsUserW    
    CreateProcessWithLogonW 
    CreateProcessWithTokenW 
    OpenProcess     
    CreateThread    
    CreateRemoteThread      
    OpenThread      
    CreateJobObjectA        
    CreateJobObjectW        
    CreateMailslotA 
    CreateMailslotW 
    CreatePipe      
    CreateNamedPipeA        
    CreateNamedPipeW        
    RegCreateKeyExA 
    RegCreateKeyExW 
    RegCreateKeyTransactedA 
    RegCreateKeyTransactedW 
    RegOpenCurrentUser      
    RegOpenKeyA     
    RegOpenKeyW     
    RegOpenKeyExA   
    RegOpenKeyExW   
    RegOpenKeyTransactedA   
    RegOpenKeyTransactedW   
    RegOpenUserClassesRoot  
    RegCreateKeyA   
    RegCreateKeyW   
    RegCloseKey     
    DuplicateHandle 
    CloseHandle      
  
What is coming up?
==================

  --> GDI objects allocation API hooks.
  
  --> GUI
  
  --> Overall performance improvements.

Contact me
==========
Do you want to participate? if yes, then contact me at anshulgoel27@gmail.com
