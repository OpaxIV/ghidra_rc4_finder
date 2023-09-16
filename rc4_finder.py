# -*- coding: utf-8 -*-				 # UTF-8 encoding

# Authors: Fabio Schmidt, Jonas Eggenberg
# Assisted by the Tutor: Tim Blazytko
# Date: XX.YY.ZZZZ

# Python Script used for finding potential RC4 implementations in programs.
# Uses the ghidra API as a basis


from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex
import networkx as nx




######################################################################################################
# Find Functions with hex value 0x100
# Description: Prints every function and returns true/false if the hex number is present in said function

def searchHex(codeUnits):
	for codeUnit in codeUnits:
		codeUnitString = codeUnit.toString()
		if '0x100' in codeUnitString:
		    return True
		return False

def hexValCheck(func):
		addrSet = func.getBody()
		codeUnits = listing.getCodeUnits(addrSet, True)
		hexvalboolean = searchHex(codeUnits)                   # returns true if hex is found
		



######################################################################################################
# Counts the parameters of function(s)
# Description: prints the Name of the function, address and the parametercount

def paramCounter(func):
    parameter_count = 0
    for parameter in func.getParameters():
        parameter_count += 1
    return parameter_count

######################################################################################################
# loopCounter
# Description: Counts the loops of functions

def loopCounter(function):
	
	# getCodeBlocksContaining​(Address addr, TaskMonitor monitor) = Get all the code blocks containing the address.
	# getBody() = Get the address set for this namespace. ??
	# fm = currentProgram.getFunctionManager()					# needed for managing functions of program
	# funcs = fm.getFunctions(True)								# iterates over functions, true means forward
	# for func in funcs:
    blocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor)
    graph = nx.DiGraph()

    # iterate over blocks
    while(blocks.hasNext()):
        bb = blocks.next()
        dest = bb.getDestinations(monitor) 	# Get an Iterator over the CodeBlocks that are flowed to from this CodeBlock.
        while(dest.hasNext()):
            dbb = dest.next()
            #graph.add_edge(bb, dbb.getDestinationBlock())
            graph.add_edge(bb.getName(), dbb.getDestinationBlock().getName())

    loopcount = 0

    # walk over all strongly connected components
    for scc in nx.strongly_connected_components(graph):
        # check for self-loop
        if len(scc) == 1:
            # will only be taken once
            for node in scc:
                # if node has an edge to itself
                if node in graph.successors(node):
                    loopcount += 1
        # SCC has more than one element -> loop
        else:
            loopcount += 1


		#print("  Func: {}, LoopCount: {}".format(func, loopcount))
    return loopcount





######################################################################################################


if __name__ == "__main__":
	
    blockModel = BasicBlockModel(currentProgram)
    listing = currentProgram.getListing()		
    
    fm = currentProgram.getFunctionManager()					# needed for managing functions of program
    funcs = fm.getFunctions(True)								# iterates over functions, true means forward
	
    for func in funcs:

        output = "  Func: {:<30}            |            HexValue: {:^}            |             ParamCount: {:^}            |             LoopCount: {:>}"
        print(output.format(func, hexValCheck(func), paramCounter(func), loopCounter(func)))
