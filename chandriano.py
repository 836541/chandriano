# /undeadwarlock
# GPL3.0-or-foward

from win32security import LookupPrivilegeValue, SE_DEBUG_NAME
from ctypes import wintypes
from setup_apis import *
from ctypes import *
import optparse
import re 
import os


def arguments():
    parser = optparse.OptionParser() 

    parser.add_option("-l", "--live", dest= "live", action= "store_true", default=False, help= "-r for real time process monitoring")
    parser.add_option("-p", "--pid", dest= "processid", default=False, type= "int", help= "pid to scan, only use if you want to scan only one process")
    parser.add_option("-s", "--string", dest= "string", default= None, help= "A specific string you want to scan")
    parser.add_option("-d", "--database", dest= "database", default= False, help= "Txt with strings to scan. Auto converted considering Endianess. Read docs to check syntax")
    (inputs, args) = parser.parse_args() 

    if inputs.realtime and inputs.processid and inputs.ondemand:
        parser.error("[x] Please use only one scan method")

    if not inputs.realtime and not inputs.processid and not inputs.ondemand:
        parser.error("[x] Please choose a scan method")

    if inputs.string and inputs.database and inputs.rules:
        parser.error("[x] Choose only one string method: -s, -r or -d")


    return (inputs.realtime, inputs.processid, inputs.string, inputs.database)

def setDebugPriv():    # Getting Debug Privileges for Memory Reading

   token_handle = wintypes.HANDLE()

   if not OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,byref(token_handle)):
      print("Error:",kernel32.GetLastError())
      return False    


   luidvalue = LookupPrivilegeValue ( None, SE_DEBUG_NAME )
   if not luidvalue:
      return False

   se_debug_name_value = LUID(luidvalue)   
   LAA                 = LUID_AND_ATTRIBUTES (se_debug_name_value,SE_PRIVILEGE_ENABLED)
 
   tkp = TOKEN_PRIVILEGES (1, LAA)


   if not AdjustTokenPrivileges(token_handle, False, byref(tkp), sizeof(tkp), None, None):
       print("Error:",GetLastError)
       CloseHandle(token_handle)       
       return False

   return True        


def memscanner(pid, malware):          

    if pid == os.getpid():
        return False
    
    setDebugPriv()  

    process = OpenProcess (PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, False, pid)                        
    if not process: 
      return False
          
   
    system_info = SYSTEM_INFO()
    GetSystemInfo ( byref(system_info) )        
    MaxAppAdress = system_info.lpMaximumApplicationAdress  
    
    VirtualQueryEx = VirtualQueryEx64
    mbi            = MEMORY_BASIC_INFORMATION64()

    memset (byref(mbi), 0, sizeof(mbi))
    Adress      = 0
    BytesRead   = c_size_t (0)
    result   = 0
 
   
    while MaxAppAdress > Adress:           

        if not VirtualQueryEx(process, Adress, byref(mbi), sizeof(mbi)):
               return False
        
        if mbi.State == MEM_COMMIT:   
                               
                 try:
                     ContentsBuffer = create_string_buffer(mbi.RegionSize)
                     
                 except:
                     pass


                 if not ReadProcessMemory(process, Adress, ContentsBuffer, mbi.RegionSize, byref(BytesRead)):              
                    Adress += mbi.RegionSize          
                    continue

                 else:
                      for x in malware:
                        if x in ContentsBuffer.raw:   

                                result += 1
                                

        Adress += mbi.RegionSize         
  
    return result


def main():
    realtime, userpid, userstring, database = arguments()

    def Endianess(string):
        endian = str()
        while len(endian) != len(string):
            endian += string[len(string)-1 - len(endian)]

        return endian

    if userstring:
        malware = [bytes(userstring, "ascii")]
        malware += [bytes(Endianess(userstring), "ascii")]
    
    
    if database: 

        with open(database, "r") as stringsdb:
            malware = stringsdb.read().splitlines()
        

        for item in malware:
            itemindex = malware.index(item)
            try:
               malware[itemindex] = bytes(malware[itemindex], "ascii")
            except:
                pass
            try:
                malware += [bytes(Endianess(item), "ascii")]
            except:
                pass

    if userpid:
        if not memscanner(userpid, malware):
            print("\n[!] String not found in Process Virtual Memory")
        else: 
            print(f"[!] {userpid} is Malware ")

    if realtime:
        index = 0 
        line  = 0

        while True:
            with open("WATCHER", "r") as file: 
                content = file.readlines()
            try:
                regex = re.findall(r"(([0-9]*),)", content[line])
                pids  = [int(processid[1]) for processid in regex]
            except:
                continue

            try: 
                pid = pids[index]
                print(pid)
                index += 1 
                if index > 9:
                   index = 0
                   line += 1
                if memscanner(pid, malware):
                   with open("RESULT", "a") as file:
                      file.write(f"{pid} is Malware\n")
                   windll.user32.MessageBoxA(0, b"MALWARE FOUND", b"ALERT", 4)

            except: 
                continue 

    return 1 


if __name__ == "__main__":

   main()


        

        

       
          


    




        
        
                

        

                  
                
                

                

                







            
















    







  

 














  



