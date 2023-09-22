

from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex
import networkx as nx






def hexCheck(func):
    # per function
    addrSet = func.getBody()                                        # Get the address set for this namespace.  
    codeUnits = listing.getCodeUnits(addrSet, True)                 # get a CodeUnit iterator that will iterate over the entire address space. True means forward

    # per codeunit    
    for codeUnit in codeUnits:
        codeUnitString = codeUnit.toString()
        if '0x100' in codeUnitString:
            return True

    return False	


def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


if __name__ == "__main__":
	blockModel = BasicBlockModel(currentProgram)
	listing = currentProgram.getListing()		
	functionManager = currentProgram.getFunctionManager()					# needed for managing functions of program
	
	# temp fix adress
	addr = getAddress(0x004018eb)
	#func = functionManager.getFunctionAt(addr).getName()	
	func = functionManager.getFunctionAt(addr)
	# print(funcName)
	print(hexCheck(func))
