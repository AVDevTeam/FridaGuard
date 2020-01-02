from abc import ABC, abstractmethod

class ArgReader(ABC):
    def __init__(self, position):
        self.position = position
        
    @abstractmethod
    def genStab(self):
        pass
        
class IntReader(ArgReader):
    def genStab(self):
        return """
        argsBag.arg{position} = args[{position}];
""".format(position=self.position)

class ASCIstrReader(ArgReader):
    def genStab(self):
        return """
        var temp = new NativePointer(args[{position}]);
        argsBag.arg{position} = temp.readCString();
""".format(position=self.position)

class UTF16strReader(ArgReader):
    def genStab(self):
        return """
        var temp = new NativePointer(args[{position}]);
        argsBag.arg{position} = temp.readUtf16String();
""".format(position=self.position)
    