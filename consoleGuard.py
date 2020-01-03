from FridaGuard import *
import json, re, sys, os

class ConsoleDefSession(SessionInterceptor):
    kill_on_violation = False # defines whether to kill violating process or not
    signatures_path = 'cmd_discovery_signatures.json'
    
    # implements attack detection logic
    def ReadConsoleCallback(self, args, data):
        for s in self.signatures:
            if s.match(args['arg1']):
                print('[!] Found suspicious command usage ({cmd}: possible {attack_type}).'.format(cmd=args['arg1'].split('\r\n')[0], attack_type=self.signatures[s]))
                return (True & self.kill_on_violation)
        return False

    def __init__(self, session):
        print("[*] Initializing...")
        print("[*] Loading signatures...")
        # loads and initializes regular expressions list
        if not os.path.isfile(self.signatures_path):
            print("[!] Signatures file not found {sign_file}.".format(sign_file=self.signatures_path))
            sys.exit(1)
        try:
            signatures_raw = json.load(open(self.signatures_path, 'r'))
        except:
            print("[!] Invalid signatures file format, expecting JSON.")
            sys.exit(1)
        self.signatures = {}
        for e in signatures_raw:
            for expression in signatures_raw[e]:
                self.signatures[re.compile(expression, re.IGNORECASE)] = e
        print("[+] Loaded signatures from {sign_file}.".format(sign_file=self.signatures_path))
        print("[*] Setting up API-hooks...")        
        # defines target functions
        funcMap = InterceptMap()
        funcMap.add('kernel32.dll', 'ReadConsoleA', [IntReader(0), ASCIstrReader(1)], self.ReadConsoleCallback, onLeave=True)
        funcMap.add('kernel32.dll', 'ReadConsoleW', [IntReader(0), UTF16strReader(1)], self.ReadConsoleCallback, onLeave=True)
        super().__init__(session, funcMap)
        print("[+] API-hooks were initialized.")
        self.start()
        print("[+] Started...")

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