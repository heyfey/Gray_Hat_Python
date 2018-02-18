import my_debugger

debugger = my_debugger.debugger()

pid = input("""Enter the PID of the process to attach to
    (you can get it from Task Manager): """)

debugger.attach(int(pid))

debugger.detach()
