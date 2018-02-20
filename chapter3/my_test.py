import my_debugger

debugger = my_debugger.debugger()

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
    print("[**] Rax: 0x%012x" % thread_context.Rax)
    print("[**] Rcx: 0x%012x" % thread_context.Rcx)
    print("[**] Rdx: 0x%012x" % thread_context.Rdx)
    print("[**] Rbx: 0x%012x" % thread_context.Rbx)
    print("[**] Rsp: 0x%012x" % thread_context.Rsp)
    print("[**] Rbp: 0x%012x" % thread_context.Rbp)
    print("[**] Rsi: 0x%012x" % thread_context.Rsi)
    print("[**] Rdi: 0x%012x" % thread_context.Rdi)
    print("[*] END DUMP\n")

debugger.detach()
