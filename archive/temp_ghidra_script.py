#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar


from ghidra.util.graph import DirectedGraph
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex


def funcIterator():
	fm = currentProgram.getFunctionManager()
	funcs = fm.getFunctions(True) # True means 'forward'
	for func in funcs: 
    		print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))


# returns any adress as object
def getMyAddress(address):
	return currentProgram.getAddressFactory().getAddress(str(hex(address)))
    


def getNextAddress(address, offset):
    return getMyAddress(address).add(offset)
    
    
def getCurrAddress():
    return currentLocation.getAddress()


# address = getAddress(0x400000)
# next_address = address.add(5)
# current_address = currentLocation.getAddress()



def main():
    print str(getMyAddress(0x400000))
    print(getNextAddress(0x400000,5))
    print(getCurrAddress())


if __name__ == '__main__':
    main()
