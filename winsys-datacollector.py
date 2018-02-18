"""
Author: Kevin Turkington (Zainkai)
Date: 2/17/2018
Class: CS 373 (Defense Against the Dark Arts)
dependencies:
- wmi
- pefile
- psutil
- pypiwin32
"""
import wmi, sys, psutil, os, pefile

def listRunningProcs():
    """
    List all running processes
    """
    print("listing processes...")
    winApi = wmi.WMI()
    for process in winApi.Win32_Process():
        print(process.ProcessId, process.Name)
        print("\tthread count:", process.ThreadCount)
        #print(process)

def listProcThreads(pid): #pid must be a string
    """
    Lists all threads for a specfic process
    
    PID: must be a valid running process
    """
    winApi = wmi.WMI()
    print("finding threads, this will take a second...")
    for thread in winApi.Win32_Thread(ProcessHandle=pid):
        print(thread)

def listThreads():
    """
    Lists all threads for all processes
    """
    winApi = wmi.WMI()
    print("finding threads, this will take a second...")
    for thread in winApi.Win32_Thread():
        print(thread, flush=True)

def listModules():
    """
    Lists all running modules (DLLs)
    """
    p = psutil.Process( os.getpid() )
    for dll in p.memory_maps():
        print(dll.path, flush=True)

def listTextAddr(moduleName):
    """
    Lists all text sections for a module
    """
    #example moduleName
    # C:\\Windows\\SysWOW64\\ntdll.dll
    try:
        pe = pefile.PE(moduleName)
        for section in pe.sections:
            if b'.text' in section.Name:
                print("Module: ", moduleName, "section: ",section.Name, "addr: ", hex(section.Misc_PhysicalAddress), flush=True)
                #print(section)
    except:
        print("Module not found.")
        print("module name format: C:/Windows/SysWOW64/ntdll.dll")

def listPEAddrs():
    """
    lists all text sections for all modules
    """
    p = psutil.Process( os.getpid() )
    for dll in p.memory_maps():
        try:
            listTextAddr(dll.path)
        except:
            pass

def getDataAtDLLNAME(moduleName):
    """
    Displays the hex data for a specfic module
    """
    try:
        pe = pefile.PE(moduleName)
        for section in pe.sections:
            print(section.Name)
            print("----------------------------------")
            print(section.get_data(), flush=True)
            print("----------------------------------")
    except:
        print("Module not found.")
        print("module name format: C:/Windows/SysWOW64/ntdll.dll")

if __name__ == "__main__":
    if "-h" in sys.argv or "-help" in sys.argv:
        print("-h -help : to display help text")
        print("-lrp : to list running processes")
    elif "-lrp" in sys.argv:    # problem 1 list running processes
        listRunningProcs()
    elif "-lt" in sys.argv:     # problem 2 list threads
        ARGS = sys.argv[2:]
        if len(ARGS) == 0:
            listThreads()
        else:
            listProcThreads(ARGS[0])
            print("If nothing has printed Pid not longer exists")
    elif "-lm" in sys.argv:     # problem 3 list all loaded modules (DLLs)
        listModules()
    elif "-la" in sys.argv:     # problem 4 show all the executable pages within the processes (.text sections of PE)
        ARGS = sys.argv[2:]
        if len(ARGS) == 0:
            listPEAddrs()
        else:
            newModuleName = (ARGS[0]).replace("/","\\\\")
            #print(newModuleName)
            listTextAddr(newModuleName)
    elif "-gd" in sys.argv and len(sys.argv[2:]) == 1: # problem 5 Gives us a capability to read the memory
        ARGS = sys.argv[2:]
        newModuleName = (ARGS[0]).replace("/","\\\\")
        getDataAtDLLNAME(newModuleName)
    else:
        print("Invalid Command")
        