from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32

class debugger():
    def __init__(self):
        print("init")
        # pass
    
    def load(self, path_to_exe):
        print("load")
        # pass
        
        
if __name__ == '__main__':
    debugger = debugger()
    debugger.load("C:\Windows\System32\calc.exe")