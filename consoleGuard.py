from FridaDef import Connector, SessionInterceptor, InterceptMap
import json, re, sys

debug_print = True # defines whether to kill violating process or not

class ConsoleDefSession(SessionInterceptor):
    # implements attack detection logic
    def ReadConsoleCallback(self, args):
        for s in self.signatures:
            if s.match(args[1]):
                if debug_print:
                    print(self.signatures[s])
                return (True & (not debug_print))
        return False

    def __init__(self, session):
        print("initializing...")
        
        # loads and initializes regular expressions list
        signatures_raw = json.load(open('signatures.json', 'r'))
        self.signatures = {}
        for e in signatures_raw:
            for expression in signatures_raw[e]:
                self.signatures[re.compile(expression)] = e
                
        # defines target functions
        funcMap = InterceptMap()
        funcMap.add('kernel32.dll', 'ReadConsoleA', ['int', 'ASCIstr'], self.ReadConsoleCallback, onLeave=True)
        funcMap.add('kernel32.dll', 'ReadConsoleW', ['int', 'UTF16str'], self.ReadConsoleCallback, onLeave=True)
        super().__init__(session, funcMap)
        self.start()
        print("started...")

if __name__ == "__main__":
    try:
        target = sys.argv[1]
    except:
        print("Usage: python consoleGuard.py <target>")
        sys.exit(1)
    try:
        target = int(target, 10) # try to interpret the input as PID
    except: 
        pass
    c = Connector(ConsoleDefSession)
    s = c.attach(target)
    temp = input('')