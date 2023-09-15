# -*- coding: utf-8 -*-				 # UTF-8 encoding


# Remark: netwx is needed to work (version 1.10 or lower, since greater versions only support python 3.XX)
# Remark 2: install netwx via pip and python 2.7.X
# URLs:
# https://networkx.org/documentation/networkx-2.7/release/api_1.10.html
# https://pip.pypa.io/en/stable/installation/

# Install Instructions:
# install python 2.7.XX (we used 2.7.15)
# Using powershell, input 'pip install networkx==1.10'
# Copy everything from the folder "C:\Python27\Lib\site-packages" into your ghidra script folder

from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
# from ghidra.util.graph import DirectedGraph
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex

# copy Python2 site-packages over your ghidra_scripts directory
import networkx as nx

# global vars
blockModel = BasicBlockModel(currentProgram)
listing = currentProgram.getListing()


# def of a basic block:
# int foo(x, y) {
#   // block A
#   int result = 0;
#   if x < y {
#     // block B
#         result = 1
#   } else {
#      /// block c
#     result = 2
#   }
#   /// block d
#   return result
# }



# create a digraph PER function
def loopCounter():
	
	# getCodeBlocksContaining​(Address addr, TaskMonitor monitor) = Get all the code blocks containing the address.
	# getBody() = Get the address set for this namespace. ??
	
	fm = currentProgram.getFunctionManager()					# needed for managing functions of program
	funcs = fm.getFunctions(True)								# iterates over functions, true means forward
	for func in funcs:
		blocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor)
		graph = nx.DiGraph()

		# iterate over blocks
		while(blocks.hasNext()):
			bb = blocks.next()
			dest = bb.getDestinations(monitor) 	# Get an Iterator over the CodeBlocks that are flowed to from this CodeBlock.
			while(dest.hasNext()):
				dbb = dest.next()
				graph.add_edge(bb, dbb)

		loopcount = len([loop for loop in nx.simple_cycles(graph)])
		print("  Func: {}, LoopCount: {}".format(func, loopcount))



if __name__ == "__main__": #to be removed in final
	loopCounter()
	
