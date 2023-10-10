# -*- coding: utf-8 -*-				                            # UTF-8 encoding, because Ghidra wants it that way

# Authors: Fabio Schmidt, Jonas Eggenberg
# Assisted by the Tutor: Tim Blazytko
# Hochschule Luzern
# Date: XX.YY.ZZZZ

# Python Script used for finding potential RC4 implementations in binaries.


######################################################################################################

# Before you begin:
# NetworkX is needed for this script to work (version 1.10 or lower, since greater versions only support python 3.XX)
# Ghidra supports Python 2.7.X

# Installation Instructions:
#
# Windows:
# Install python 2.7.XX (we used 2.7.15)
# Using powershell (on Windows), input 'pip install networkx==1.10'
# After the Installation, copy everything from the folder "C:\Python27\Lib\site-packages" into your Ghidra Scripts Folder.
#
# Debian/Ubuntu:
# Same procedure, except for the installation folder of networkx: `/usr/local/lib/python3.10/dist-packages/networkx`

# URLs:
# https://networkx.org/documentation/networkx-2.7/release/api_1.10.html
# https://pip.pypa.io/en/stable/installation/

######################################################################################################



# imports
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex
import networkx as nx


######################################################################################################
# xorCheck(function)
# Description: Checks if given function contains at any point the XOR operator

def xorCheck(func):
    # per function
    addrSet = func.getBody()                                        # Get the address set for this namespace.  
    codeUnits = listing.getCodeUnits(addrSet, True)                 # get a CodeUnit iterator that will iterate over the entire address space. True means forward

    # per codeunit    
    for codeUnit in codeUnits:
        codeUnitString = codeUnit.toString()
        if 'XOR' in codeUnitString:
            return True

    return False

######################################################################################################
# hexCheck(function)
# Description: Checks if given function contains at any point the hex value 0x100

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
		

######################################################################################################
# paramCouunter(function)
# Description: Counts the parameters of the given function

def paramCounter(func):
    parameter_count = 0
    for parameter in func.getParameters():                              # Get all function parameters
        parameter_count += 1
    return parameter_count

######################################################################################################
# loopCounter(function)
# Description: Counts the loops of a function (strongly connected)

def loopCounter(function):
    blocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor)    # Get all the code blocks containing the address.
    graph = nx.DiGraph()

    # iterate over blocks
    while(blocks.hasNext()):
        bb = blocks.next()
        dest = bb.getDestinations(monitor) 	                                # Get an Iterator over the CodeBlocks that are flowed to from this CodeBlock.
        while(dest.hasNext()):
            dbb = dest.next()
            graph.add_edge(bb.getName(), dbb.getDestinationBlock().getName())

    loopcount = 0

    # walk over all strongly connected components
    for scc in nx.strongly_connected_components(graph):                     # Generate nodes in strongly connected components of graph.
        # check for self-loop
        if len(scc) == 1:
            # will only be taken once
            for node in scc:
                # if node has an edge to itself
                if node in graph.successors(node):
                    loopcount += 1
        # SCC has more than one element -> loop
        else:
            loopcount += 1                                                  # finds scc with > 1 nodes, corresponding to a default loop
    return loopcount

######################################################################################################
# possibleKSA(function)
# Description: Checks if all conditions are met for the function

def possibleKSA(func):
    if hexCheck(func) and (paramCounter(func) >= 2 and paramCounter(func) <= 5) and (loopCounter(func) >=1):
        return True
    return False

######################################################################################################
# possiblePRGA(function)
# Description: Checks if all conditions are met for the function

def possiblePRGA(func):
    if (paramCounter(func) >= 3 and paramCounter(func) <= 4) and (loopCounter(func) >=1) and xorCheck(func):
        return True
    return False

######################################################################################################
# Main

if __name__ == "__main__":
	
    blockModel = BasicBlockModel(currentProgram)
    listing = currentProgram.getListing()		
    
    fm = currentProgram.getFunctionManager()					# needed for managing functions of program
    funcs = fm.getFunctions(True)								# iterates over functions, true means forward
    funccount = 0
    pKSA = 0
    pPRGA = 0	

    for func in funcs:
        output = "  Func: {:<30}	  |      HexValue: {:^}      |        ParamCount: {:^}          |        loopCount: {:^}         |       xorCount: {:^}  |   Possible a KSA: {:>}            |             Possible a PRGA: {:>}            |"
        if possibleKSA(func):
		print(output.format(func, hexCheck(func), paramCounter(func), loopCounter(func), xorCheck(func), possibleKSA(func), possiblePRGA(func)))
		pKSA += 1
	if possiblePRGA(func):
		print(output.format(func, hexCheck(func), paramCounter(func), loopCounter(func), xorCheck(func), possibleKSA(func), possiblePRGA(func)))
		pPRGA += 1
	funccount += 1

    print(funccount)
    print(pKSA)
    print(pPRGA)
