from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32

class debugger():
    
    def __init__(self):
        self.h_process = None
        self.pid = None
        self.debugger_active = False

    """Process Attachment
    """
    def open_process(self, pid):
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        return h_process
    
    def attach(self, pid):
        self.h_process = self.open_process(pid)
        
        # We attempt to attach to the process
        # if this fails we exit the call
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
        else:
            print("[*] Unable to attach to the process.")
            
    def run(self):       
        # Now we have to poll the debuggee for
        # debugging events
        while self.debugger_active is True:
            self.get_debug_event()
            
    def get_debug_event(self):        
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE            
        
        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            kernel32.ContinueDebugEvent(debug_event.dwProcessId,
                                        debug_event.dwThreadId,
                                        continue_status)
            
    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            print("[*] Finished debugging. Exiting...")
            return True
        else:
            print("There was an error!")
            return False
        
    
    """ Thread Enumeration 
    """
    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        
        if h_thread is not None:
            return h_thread
        else:
            print("[*] Could not obtain a valid thread handle.")
            return False
        
    def enumerate_threads(self):
        thread_entry = THREADENTRY32()
        thread_list = []
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 
                                                     self.pid)
        
        if snapshot is not None:
            # You have to set the size of the struct
            # or the call will fail.
            thread_entry.dwSize = sizeof(thread_entry)
            
            success = kernel32.Thread32First(snapshot, 
                                             byref(thread_entry))
            
            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                
                success = kernel32.Thread32Next(snapshot,
                                                byref(thread_entry))
            
            kernel32.CloseHandle(snapshot)
            return thread_list
        else:
            return False
        
    def get_thread_context(self, thread_id=None, h_thread=None):
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        
        # Obtain a handle to the thread.
        if not h_thread:
            h_thread = self.open_thread(thread_id)
        
        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context
        else:
            return False
        
        
if __name__ == '__main__':
    debugger = debugger()
    pid = input("Enter the PID of the process to attach to "
                "(you can get it from Task Manager): ")
    debugger.attach(int(pid))
    
    list = debugger.enumerate_threads()
    
    # For each thread in the list we want to
    # grab the value of each of the registers.
    for thread in list:
        thread_context = debugger.get_thread_context(thread)
        
        # Now let's output the contents of some of the registers.
        print("[*] Dumping registers for thread ID: 0x%08x" % thread)
        print("[**] EIP: 0x%08x" % thread_context.Eip)
        print("[**] ESP: 0x%08x" % thread_context.Esp)
        print("[**] EBP: 0x%08x" % thread_context.Ebp)
        print("[**] EAX: 0x%08x" % thread_context.Eax)
        print("[**] EBX: 0x%08x" % thread_context.Ebx)
        print("[**] ECX: 0x%08x" % thread_context.Ecx)
        print("[**] EDX: 0x%08x" % thread_context.Edx)
        print("[*] END DUMP\n")
    
    debugger.detach()