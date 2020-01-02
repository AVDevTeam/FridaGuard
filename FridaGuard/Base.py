import frida, inspect, os, sys
from psutil import Process
from abc import ABC, abstractmethod

# another wrapper that is not used.
# initializes Frida session with the script that is named as the module where the child of this class
# is implemented.
class SessionFile(ABC):
    @abstractmethod
    def on_message(self, message, data):
        pass
        
    def __init__(self, session):
        self.session = session
        path = '.'.join(os.path.abspath(sys.modules[self.__module__].__file__).split('.')[:-1] + ['js'])
        self.script = self.session.create_script(open(path, 'r', encoding='utf-8').read())
        self.script.on('message', self.on_message)
        
    def start(self):
        self.script.load()
        
class InterceptMap(object):
    # supported argument types: strings (ascii, utf-8 (aka encoding used in windows))
    types = [
        'ASCIstr',
        'UTF16str',
        'int'
    ]

    def __init__(self):
        self.fmap = {}
    
    # override indexing operators
    def __getitem__(self, key):
        return self.fmap[key]
        
    def __setitem__(self, key, value):
        self.fmap[key] = value
    
    # method that is used in inheriting classes to declare callbacks for specific exports.
    # parameter onLeave defines whether the arguments will be processed before or after the call.
    def add(self, module, func, args, callback, onLeave=False):
        for a in args:
            if a not in self.types:
                raise ValueError('Invalid arg type')
        if module not in self.fmap:
            self[module] = {}
        self[module][func] = (args, callback, onLeave)
        
# base class that implements the logic of exports hooking.
# It generates Frida js script that uses interceptor and messaging mechanism to
# send information about the function calls to the python script where the arguments
# of the call will be passed to the provided callback.
class SessionInterceptor(ABC):
    # this method receives messages from Frida agent (send via send function in js)
    # and calls corresponding callback function (from the InterceptMap).
    # based on the result from the callback the target process will be terminated or not.
    def on_message(self, message, data):
        module = message['payload']['module']
        func = message['payload']['func']
        PID = message['payload']['PID']
        callback = self.funcMap[module][func][1]
        if callback(message['payload']['args']):
            p = Process(PID)
            p.kill()
        self.script.post({'type': 'wake', 'payload': None})
        
    # this method create Frida js script source code based on the provided InterceptMap
    def initScript(self, debug=False):
        funcMap = self.funcMap
        script = ''
        for module in funcMap.fmap:
            for func in funcMap[module]:
                varName = '{}{}'.format(module.replace('.', ''), func)
                script += 'var {varName} = Module.findExportByName("{module}", "{func}");\n'.format(varName=varName, module=module, func=func)
                script += """Interceptor.attach({varName}, {{
    onEnter: function(args) {{
        this.preArgs = [];
        var argsBag = [];""".format(varName=varName, func=func)
                argCnt = -1
                for arg in funcMap[module][func][0]: # iterates over arguments
                    argCnt += 1
                    if arg == 'UTF16str':
                        script += """
        var temp = new NativePointer(args[{argCnt}]);
        argsBag.push(temp.readUtf16String());
        this.preArgs.push(args[{argCnt}]);
""".format(argCnt=argCnt)
                    if arg == 'ASCIstr':
                        script += """
        var temp = new NativePointer(args[{argCnt}]);
        argsBag.push(temp.readCString());
        this.preArgs.push(args[{argCnt}]);
""".format(argCnt=argCnt)
                    if arg == 'int':
                        script += """
        argsBag.push(args[{argCnt}]);
        this.preArgs.push(args[{argCnt}]);
""".format(argCnt=argCnt)
                if not funcMap[module][func][2]: # check onLeave flag
                    script += """
        var toSend = {{}};
        toSend.type = "onEnter";
        toSend.PID = Process.id;
        toSend.module = "{module}";
        toSend.func = "{func}";
        toSend.args = argsBag;
        send(toSend);
        var op = recv('wake', function(value) {{}});
        op.wait();
    }},""".format(module=module, func=func)
                # onLeave
                else:
                    script += """
    }},
    onLeave: function(result) {{
        var argsBag = [];
""".format(varName=varName, func=func)
                    argCnt = -1
                    for arg in funcMap[module][func][0]:
                        argCnt += 1
                        if arg == 'UTF16str':
                            script += """       
        var temp = new NativePointer(this.preArgs[{argCnt}]);
        argsBag.push(temp.readUtf16String());
""".format(argCnt=argCnt)
                        if arg == 'ASCIstr':
                            script += """
        var temp = new NativePointer(this.preArgs[{argCnt}]);
        argsBag.push(temp.readCString());
""".format(argCnt=argCnt)
                        if arg == 'int':
                            script += """
        argsBag.push(this.preArgs[{argCnt}]);
""".format(argCnt=argCnt)
                    script += """
        var toSend = {{}};
        toSend.type = "onLeave";
        toSend.PID = Process.id;
        toSend.module = "{module}";
        toSend.func = "{func}";
        toSend.args = argsBag;
        send(toSend);
        var op = recv('wake', function(value) {{}});
        op.wait();
    }},""".format(module=module, func=func)
                script += """
}});""".format(module=module, func=func)
        if debug: # dump script for debugging
            with open('script_debug.js', 'w', encoding='utf-8') as f:
                f.write(script)
        self.script = self.session.create_script(script)
        self.script.on('message', self.on_message)
        
    # loads script to the target process
    def start(self):
        self.script.load()
        
    # this constructor is called from Connector instance
    def __init__(self, session, funcMap):
        self.session = session
        self.funcMap = funcMap
        self.initScript()
        
# wrapper for Frida python bidings (we need more wrappers)
class Connector(object):
    # initializes frida for localhost
    # sessionConstructor - class inherited from SessionInterceptor
    def __init__(self, sessionConstructor):
        self.dev = frida.get_local_device()
        self.sessionConstructor = sessionConstructor

    def attach(self, process):
        return self.sessionConstructor(self.dev.attach(process))
        