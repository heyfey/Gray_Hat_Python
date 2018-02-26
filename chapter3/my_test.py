import my_debugger
from my_debugger_defines import *

debugger = my_debugger.debugger()

pid = input("Enter the PID of the process to attach to "
            "(you can get it from Task Manager): ")

debugger.attach(int(pid))

printf_address = debugger.func_resolve(b"msvcrt.dll", b"printf")
print("[*] Address of printf: 0x%012x" % printf_address)

debugger.bp_set(printf_address) # soft breakpoint
# debugger.bp_set_hw(printf_address, 1, HW_EXECUTE) # hardware breakpoint
# debugger.bp_set_mem(printf_address, debugger.page_size) # memory breakpoint

debugger.run()

debugger.detach()

