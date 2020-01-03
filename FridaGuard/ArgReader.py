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

class BinBufferReader(ArgReader):
    def __init__(self, position, lenPosition):
        super().__init__(position)
        self.lenPosition = lenPosition
        
    def genStab(self):
        return """
        var temp = new NativePointer(args[{position}]);
        argsBag.arg{position} = "data";
        argsBag.data = temp.readByteArray(args[{lenPosition}].toInt32());
""".format(position=self.position, lenPosition=self.lenPosition)

class BinBufferReaderPtr(ArgReader):
    def __init__(self, position, lenPosition):
        super().__init__(position)
        self.lenPosition = lenPosition
        
    def genStab(self):
        return """
        var temp = new NativePointer(args[{position}]);
        var temp2 = new NativePointer(args[{lenPosition}]);
        argsBag.arg{position} = "data";
        argsBag.data = temp.readByteArray(temp2.readS32());
""".format(position=self.position, lenPosition=self.lenPosition)
    