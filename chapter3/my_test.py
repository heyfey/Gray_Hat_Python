import my_debugger

debugger = my_debugger.debugger()

pid = input("Enter the PID of the process to attach to "
            "(you can get it from Task Manager): ")

debugger.attach(int(pid))

printf_address = debugger.func_resolve(b"msvcrt.dll", b"printf")

print("[*] Address of printf: 0x%08x" % printf_address)

debugger.bp_set(printf_address)

debugger.run()

debugger.detach()

