from FridaGuard import *
import json, re, sys, os
from urllib.parse import parse_qs, unquote, urlparse

# This class implements builder pattern.
# It is used to accumulate information
# about HTTP-request and response.
class WinInetRequest(object):
    def __init__(self, handle):
        self.verb = self.host = self.relPath = self.headers = ''
        self.body = self.response = b''
        self.handle = handle
        
    def withHost(self, host):
        self.host = host
        return self
        
    def withVerb(self, verb):
        self.verb = verb
        return self
        
    def withRelPath(self, relPath):
        self.relPath = relPath
        return self
    
    def withHeaders(self, headers):
        self.headers = headers
        return self
        
    def withBody(self, body):
        self.body = body
        return self
        
    def clearResponse(self):
        self.response = b''
        
    def withResponse(self, response):
        self.response += response
        return self
        
    def __repr__(self):
        return "{}: {} {}{}\n\theaders: {}\nbody:\n{}\nresponse:\n{}".format(self.handle, self.verb, self.host, self.relPath, self.headers, unquote(self.body.decode('utf-8')), self.response)
        
    def __str__(self):
        return "{}: {} {}{}\n\theaders: {}\nbody:\n{}\nresponse:\n{}".format(self.handle, self.verb, self.host, self.relPath, self.headers, unquote(self.body.decode('utf-8')), self.response)

# This class inherties SessionInterceptor framework class
# and implements reflective XSS detection logic.
# Detectioin is based on matching XSS-signatures found in
# request parameters (GET-params and POST-data) with
# the response from server.
class WebDefSession(SessionInterceptor):
    kill_on_violation = False # defines whether to kill violating process or not
    signatures_path = 'xss_signatures.json'

    # implements attack detection logic
    def CheckResponse(self, requestData):
        matches = {}
        if requestData.body:
            try:
                postParams = parse_qs(unquote(requestData.body.decode('utf-8'))) # parse POST-params from request body
                for key in postParams:
                    for regex in self.xss_signatures:
                        cur_xss_payload_type = self.xss_signatures[regex]
                        for cur_matche in regex.findall(postParams[key][0]):
                            matches[cur_matche] = (cur_xss_payload_type, 'POST')
            except:
                print("[!] Error parsing POST data.")
        if requestData.relPath:
            try:
                getParams = parse_qs(urlparse(requestData.relPath).query) # parse GET-params from URL
                for key in getParams:
                    for regex in self.xss_signatures:
                        cur_xss_payload_type = self.xss_signatures[regex]
                        for cur_matche in regex.findall(getParams[key][0]):
                            matches[cur_matche] = (cur_xss_payload_type, 'GET')
            except:
                print("[!] Error parsing GET params.")
        # check reflections in response
        if requestData.response:
            response = requestData.response.decode('utf-8')
            for match in matches:
                if response.find(match) != -1:
                    print('[!] Found XSS-payload (type "{ptype}") {payload} injected via {verb}-parameter.'.format(ptype=matches[match][0], payload=match, verb=matches[match][1]))            
                    return (True & self.kill_on_violation)
        return False
           
    # Most hooks are used to trace HTTP-requests made via wininet.dll (by handle).
    def InternetConnectCallback(self, args, data):
        handle = args['ret']
        self.requests[handle] = WinInetRequest(handle).withHost(args['arg1'])
        
    def HttpOpenRequestCallback(self, args, data):
        handle = args['arg0']
        if handle not in self.requests:
            self.requests[handle] = WinInetRequest(handle)
        self.requests[handle].withVerb(args['arg1'] if args['arg1'] != None else 'GET').withRelPath(args['arg2'])
        
    def HttpAddRequestHeadersCallback(self, args, data):
        handle = args['arg0']
        if handle not in self.requests:
            self.requests[handle] = WinInetRequest(handle)
        self.requests[handle].withHeaders(args['arg1'])
        
    def HttpSendRequestCallback(self, args, data):
        handle = args['arg0']
        if handle not in self.requests:
            self.requests[handle] = WinInetRequest(handle)
        self.requests[handle].withHeaders(args['arg1'])
        self.requests[handle].clearResponse()
        if data:
            self.requests[handle].withBody(data)
    
    # This callaback receives response and calls CheckResponse method.
    def InternetReadFileCallback(self, args, data):
        handle = args['arg0']
        if handle not in self.requests:
            self.requests[handle] = WinInetRequest(handle)
        self.requests[handle].withResponse(data)
        return self.CheckResponse(self.requests[handle])

    def __init__(self, session):
        self.requests = {}
        print("[*] Initializing...")
        print("[*] Loading signatures...")
        # load XSS-payloads signatures
        if not os.path.isfile(self.signatures_path):
            print("[!] Signatures file not found {sign_file}.".format(sign_file=self.signatures_path))
            sys.exit(1)
        try:
            signatures_raw = json.load(open(self.signatures_path, 'r'))
        except:
            print("[!] Invalid signatures file format, expecting JSON.")
            sys.exit(1)
        signatures = {}
        for stype in signatures_raw:
            for s in signatures_raw[stype]:
                signatures[re.compile(s, re.IGNORECASE)] = stype
        self.xss_signatures = signatures
        print("[+] Loaded signatures from {sign_file}.".format(sign_file=self.signatures_path))
        print("[*] Setting up API-hooks...") 
        # defines target functions
        funcMap = InterceptMap()
        funcMap.add('wininet.dll', 'InternetConnectA', [ASCIstrReader(1)], self.InternetConnectCallback, onLeave=True)
        funcMap.add('wininet.dll', 'InternetConnectW', [UTF16strReader(1)], self.InternetConnectCallback, onLeave=True)
        funcMap.add('wininet.dll', 'HttpOpenRequestA', [
                                                        IntReader(0),     # handle
                                                        ASCIstrReader(1), # verb
                                                        ASCIstrReader(2)  # relative path
                                                        ], self.HttpOpenRequestCallback)
        funcMap.add('wininet.dll', 'HttpOpenRequestW', [
                                                        IntReader(0), 
                                                        UTF16strReader(1),
                                                        UTF16strReader(2)
                                                        ], self.HttpOpenRequestCallback)
        funcMap.add('wininet.dll', 'HttpAddRequestHeadersA', [
                                                        IntReader(0),      # handle
                                                        ASCIstrReader(1)   # headers
                                                        ], self.HttpAddRequestHeadersCallback)
        funcMap.add('wininet.dll', 'HttpAddRequestHeadersW', [
                                                        IntReader(0),       # handle
                                                        UTF16strReader(1)   # headers
                                                        ], self.HttpAddRequestHeadersCallback)
        funcMap.add('wininet.dll', 'HttpSendRequestA', [
                                                        IntReader(0),         # handle
                                                        ASCIstrReader(1),     # headers
                                                        BinBufferReader(3, 4) # body
                                                        ], self.HttpSendRequestCallback)                                                         
        funcMap.add('wininet.dll', 'HttpSendRequestW', [
                                                        IntReader(0),         # handle
                                                        UTF16strReader(1),    # headers
                                                        BinBufferReader(3, 4) # body
                                                        ], self.HttpSendRequestCallback)
        funcMap.add('wininet.dll', 'InternetReadFile', [
                                                        IntReader(0),         # handle
                                                        UTF16strReader(1),    # headers
                                                        BinBufferReaderPtr(1, 3) # body
                                                        ], self.InternetReadFileCallback, onLeave=True)                                                
        super().__init__(session, funcMap)
        print("[+] API-hooks were initialized.")
        self.start()
        print("[+] Started...")

if __name__ == "__main__":
    try:
        target = sys.argv[1]
    except:
        print("Usage: python webGuard.py <target>")
        sys.exit(1)
    try:
        target = int(target, 10) # try to interpret the input as PID
    except: 
        pass
    c = Connector(WebDefSession)
    s = c.attach(target)
    temp = input('')