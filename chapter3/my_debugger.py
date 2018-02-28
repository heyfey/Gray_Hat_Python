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
        self.hardware_breakpoints = {}
        
        # Here let's determine an d store
        # the default page size for the system.
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize
        
        self.guarded_pages = []
        self.memory_breakpoints = {}

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
                self.exception = \
                debug_event.u.Exception.ExceptionRecord.ExceptionCode
                
                self.exception_address = \
                debug_event.u.Exception.ExceptionRecord.ExceptionAddress
                
                print("[*] Exception Code: %d Exception Address: 0x%012x" 
                      % (self.exception, self.exception_address))
                
                if self.exception == EXCEPTION_ACCESS_VIOLATION:
                    print("[*] Access Violation Detected.")
                    
                # If a breakpoint is detected, we call an internal
                # handler.
                elif self.exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
                
                elif self.exception == EXCEPTION_GUARD_PAGE:
                    print("[*] Guard Page Access Detected.")
                    
                elif self.exception == EXCEPTION_SINGLE_STEP:
                    print("[*] Single Stepping.")  
                    self.exception_handler_single_step()
                             
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
            return context64
        else:
            return False
        
        
    """ Exception Handler
    """
    def exception_handler_breakpoint(self):
        print("[*] Inside the breakpoint handler.")
        
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
            
            # Remove breakpoint
            self.write_process_memory(self.exception_address, 
                                      self.breakpoints[self.exception_address])
            
            context = self.get_thread_context(h_thread=self.h_thread)
            context.Rip -= 1
            kernel32.SetThreadContext(self.h_thread, byref(context))
            del self.breakpoints[self.exception_address]
            print("[*] Breakpoint removed.")
            
        
        return DBG_CONTINUE
    
    def exception_handler_single_step(self):
        # Comment from PyDbg:
        # determine if this single step event occurred in reaction to a
        # hardware breakpoint and grab the hit breakpoint.
        # according to the Intel docs, we should be able to check for
        # the BS flag in Dr6. but it appears that Windows
        # isn't properly propagating that flag down to us.
        if self.context.Dr6 & 0x01 and 0 in self.hardware_breakpoints:
            slot = 0
        elif self.context.Dr6 & 0x02 and 1 in self.hardware_breakpoints:
            slot = 1
        elif self.context.Dr6 & 0x04 and 2 in self.hardware_breakpoints:
            slot = 2
        elif self.context.Dr6 & 0x08 and 3 in self.hardware_breakpoints:
            slot = 3
        else:
            # This was'nt an INT1 generated by a hw breakpoint.
            continue_status = DBG_EXCEPTION_NOT_HANDLED
            
        # Now let's remove the breakpoint from the list.
        if self.bp_del_hw(slot):
            continue_status = DBG_CONTINUE
            
        print("[*] Hardware breakpoint removed.")
            
        return continue_status
    

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
        print("[*] Setting breakpoint at: 0x%012x" % address)
        if address not in self.breakpoints:
            try:
                # store the original byte
                original_byte = self.read_process_memory(address, 1)
                
                # write the INT3 opcode
                self.write_process_memory(address, b"\xCC")
                
                # register the break point in our internal list
                self.breakpoints[address] = original_byte
            except:
                return False
            
        return True

    
    def read_process_memory(self, address, length):
        data = ""
        read_buf = create_string_buffer(length)
        count = c_ulonglong(0)
        
        from ctypes import wintypes as w
        kernel32.ReadProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, w.LPVOID, c_size_t, POINTER(c_size_t)]
        kernel32.ReadProcessMemory.restype = w.BOOL
        if not kernel32.ReadProcessMemory(self.h_process,
                                          address,
                                          read_buf,
                                          length,
                                          byref(count)):
            return False
        else:
            data = read_buf.raw
            return data
        
    def write_process_memory(self, address, data):
        count = c_ulonglong(0)
        length = len(data)
        
        c_data = c_char_p(data[count.value:])
        
        from ctypes import wintypes as w
        kernel32.WriteProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, w.LPVOID, c_size_t, POINTER(c_size_t)]
        kernel32.WriteProcessMemory.restype = w.BOOL
        if not kernel32.WriteProcessMemory(self.h_process,
                                           address,
                                           c_data,
                                           length,
                                           byref(count)):
            return False
        else:
            return True
        
    """ Hardware Breakpoints
    """
    def bp_set_hw(self, address, length, condition):
        # Check for a valid length value.
        if length not in (1, 2, 4):
            return False
        else:
            length -= 1
        
        # Check for a valid condition.
        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            return False
        
        # Check for available slots.
        if 0 not in self.hardware_breakpoints:
            available = 0
        elif 1 not in self.hardware_breakpoints:
            available = 1
        elif 2 not in self.hardware_breakpoints:
            available = 2
        elif 3 not in self.hardware_breakpoints:
            available = 3
        else:
            return False
        
        # We want to set the debug register in every thread.
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)
            # Enable the appropriate flag in the DR7
            # register to set the breakpoint.
            context.Dr7 |= 1 << (available * 2)
            
            # Save the address of the break point in the
            # free register that we found.
            if available == 0: context.Dr0 = address
            elif available == 1: context.Dr1 = address
            elif available == 2: context.Dr2 = address
            elif available == 3: context.Dr3 = address
            
            # Set the breakpoint condition.
            context.Dr7 |= condition << ((available * 4) + 16)
            
            # Set the length
            context.Dr7 |= condition << ((available * 4) + 18)
            
            # Set thread context with the break set.
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))
        
        # Update the internal hardware breakpint array at the used
        # slot index.
        self.hardware_breakpoints[available] = (address, length, condition)
        
        return True 
    
    def bp_del_hw(self, slot):
        # Disable the breakpoint for all active threads
        for thread_id in self.enumerate_threads():
            
            context = self.get_thread_context(thread_id=thread_id)
            
            # Reset the flags to remove the breakpoint.
            context.Dr7 &= ~(1 << (slot * 2))
            
            # Zero out the address.
            if slot == 0: context.Dr0 = 0x00000000
            elif slot == 1: context.Dr1 = 0x00000000
            elif slot == 2: context.Dr2 = 0x00000000
            elif slot == 3: context.Dr3 = 0x00000000
            
            # Remove the condition flag.
            context.Dr7 &= ~(3 << ((slot * 4) + 16))
            
            # Remove the length flag.
            context.Dr7 &= ~(3 << ((slot * 4) + 18))
            
            # Reset the thread's context with the breakpoint removed.
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))
            
        # Remove the breakpoint from internal list.
        del self.hardware_breakpoints[slot]
        
        return True
    
    """Memory Breakpoints
    """
    def bp_set_mem(self, address, size):
        
        mbi = MEMORY_BASIC_INFORMATION64()
        
        # If our VirtualQueryEx() call doesn't return
        # a full-sized MEMORY_BASIC_INFORMATION
        # then return False        
        from ctypes import wintypes as w
        kernel32.VirtualQueryEx.argtypes = [w.HANDLE, w.LPVOID, POINTER(MEMORY_BASIC_INFORMATION64), c_size_t]
        kernel32.VirtualQueryEx.restype = c_size_t
        
        if kernel32.VirtualQueryEx(self.h_process, 
                                   address, 
                                   byref(mbi), 
                                   sizeof(mbi)) < sizeof(mbi):
            print(kernel32.GetLastError())
            return False
        
        current_page = mbi.BaseAddress
        
        # We will set the permissions on all pages that are
        # affected by our memory breakpoint.
        while current_page <= address + size:
            
            # Add the page to the list; this will
            # differentiate our guarded pages from those
            # that were set by the OS or the debuggee process.
            self.guarded_pages.append(current_page)
            
            old_protection = c_ulong(0)
            
            kernel32.VirtualProtectEx.argtypes = [w.HANDLE, w.LPVOID, c_size_t, w.DWORD, POINTER(DWORD)]
            kernel32.VirtualProtectEx.restype = w.BOOL
            if not kernel32.VirtualProtectEx(self.h_process, 
                                             current_page, 
                                             size,
                                             mbi.Protect | PAGE_GUARD,
                                             byref(old_protection)):
                return False
            
            # Increase our range by the size of the
            # default system memory page size.
            current_page += self.page_size
        
        # Add the memory breakpoint to our global list.
        self.memory_breakpoints[address] = (address, size, mbi)
        
        return True
        
    
               
if __name__ == '__main__':
    debugger = debugger()
    
    pid = input("Enter the PID of the process to attach to "
                "(you can get it from Task Manager): ")
    
    debugger.attach(int(pid))
    
    printf_address = debugger.func_resolve(b"msvcrt.dll", b"printf")
    print("[*] Address of printf: 0x%012x" % printf_address)

    # debugger.bp_set(printf_address) # soft breakpoint
    # debugger.bp_set_hw(printf_address, 1, HW_EXECUTE) # hardware breakpoint
    debugger.bp_set_mem(printf_address, debugger.page_size) # memory breakpoint
    
    debugger.run()
    
    debugger.detach()