from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32

class debugger():
    
    def __init__(self):
        self.h_process = None
        self.pid = None
        self.debugger_active = False
        self.h_thread = None
        self.context = None    
          
        self.exception = None
        self.exception_address = None       
        
        self.breakpoints = {}
        self.first_breakpoint = True

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
            # Let's obtain the thread and context information.
            self.h_thread = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(h_thread=self.h_thread)
            
            print("Event Code: %d Thread ID: %d" %
                  (debug_event.dwDebugEventCode, debug_event.dwThreadId))
            
            # If the event code is an exception, we want to
            # examine it further.
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                # Obtain the exception code
                exception = \
                debug_event.u.Exception.ExceptionRecord.ExceptionCode
                
                self.exception_address = \
                debug_event.u.Exception.ExceptionRecord.ExceptionAddress
                
                if exception == EXCEPTION_ACCESS_VIOLATION:
                    print("Access Violation Detected.")
                    
                    # If a breakpoint is detected, we call an internal
                    # handler.
                elif exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
                
                elif exception == EXCEPTION_GUARD_PAGE:
                    print("Guard Page Access Detected.")
                    
                elif exception == EXCEPTION_SINGLE_STEP:
                    print("Single Stepping.")  
                             
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
        context64 = WOW64_CONTEXT()
        context64.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        
        # Obtain a handle to the thread.
        if not h_thread:
            h_thread = self.open_thread(thread_id)
        
        if kernel32.GetThreadContext(h_thread, byref(context64)):
            kernel32.CloseHandle(h_thread)
            return context64
        else:
            return False
        
        
    """ Exception Handler
    """
    def exception_handler_breakpoint(self):
        print("[*] Inside the breakpoint handler.")
        print("[*] Exception Address: 0x%08x" % self.exception_address)
        
        # Check if the breakpoint is one that we set.
        if self.exception_address not in self.breakpoints:
            # If it is the first Windows driven breakpoint
            # then let's just continue on.
            if self.first_breakpoint == True:
                self.first_breakpoint = False
                print("[*] Hit the first breakpoint.")
                return DBG_CONTINUE
        else:
            print("[*] Hit user defined breakpoint.")
        
        return DBG_CONTINUE
    
    
    """ Soft Breakpoints
    """
    def func_resolve(self, dll, function):
        GetModuleHandle = kernel32.GetModuleHandleA
        # For 64-bit
        GetModuleHandle.argtypes = [c_char_p]
        GetModuleHandle.restype = c_void_p
        
        handle = GetModuleHandle(dll)
        
        GetProcAddress = kernel32.GetProcAddress
        GetProcAddress.argtypes = [c_void_p, c_char_p]
        GetProcAddress.restype = c_void_p
        
        address = GetProcAddress(handle, function)
        
        return address
    
    def bp_set(self, address):
        print("[*] Setting breakpoint at: 0x%08x" % address)
        if address not in self.breakpoints:
            try:
                # store the original byte
                original_byte = self.read_process_memory(address, 1)
                
                # write the INT3 opcode
                self.write_process_memory(address, "\xCC")
                
                # register the break point in our internal list
                self.breakpoints[address] = (original_byte)
            except:
                return False
            
        return True

    
    def read_process_memory(self, address, length):
        data = ""
        read_buf = create_string_buffer(length)
        count = c_ulong(0)
        
        if not kernel32.ReadProcessMemory(self.h_process,
                                          address,
                                          read_buf,
                                          length,
                                          byref(count)):
            return False
        else:
            data += read_buf.raw
            return data
        
    def write_process_memory(self, address, data):
        count = c_ulong(0)
        length = len(data)
        
        c_data = c_char_p(data[count.value:])
        
        if not kernel32.WriteProcessMemory(self.h_process,
                                           address,
                                           c_data,
                                           length,
                                           byref(count)):
            return False
        else:
            return True
        
               
if __name__ == '__main__':
    debugger = debugger()
    
    pid = input("Enter the PID of the process to attach to "
                "(you can get it from Task Manager): ")
    
    debugger.attach(int(pid))
    
    printf_address = debugger.func_resolve(b"msvcrt.dll", b"printf")

    print("[*] Address of printf: 0x%08x" % printf_address)

    debugger.bp_set(printf_address)
    
    debugger.run()
    
    debugger.detach()