# Process Creation Logger
# Logs 10 PIDs per line in a output file

import wmi 

def process_monitor():        # Real time Proc Monitor that captures the pid of new processes
   objCom = wmi.WMI()
   new_procs = objCom.watch_for(notification_type="Creation", wmi_class="Win32_Process")
   count = 0
   with open("WATCHER", "w") as output:
       output.close() 
       
   while True:
      processo = new_procs()
      with open ("WATCHER","a") as output:
        if count == 9:
            output.write(f"{processo.ProcessId},\n")
            count = 0

        else: 
            output.write(f"{processo.ProcessId},")
            count += 1

if __name__ == "__main__":
    process_monitor()

