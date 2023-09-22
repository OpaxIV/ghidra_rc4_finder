from ghidra.util.graph import DirectedGraph
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex



def mainLoopCounter():
	
	digraph = DirectedGraph()
	Listing = currentProgram.getListing()
	Fm = currentProgram.getFunctionManager()


    # Returns a new address with the specified offset in the default address space.
	knownFunctionAddress = toAddr("004018eb")                                     # temp hardcoded ksa addr
	
    function = getFunctionContaining(knownFunctionAddress)
	digraph.add(Vertex(function))
	vertices = digraph.vertexIterator()
	while vertices.hasNext():
   		vertex = vertices.next()
		loopCount = digraph.loopDegree(vertex)                                    # Returns numLoops as a double.
		print("  Vertex: {} {}(key: {})".format(vertex, loopCount, vertex.key())) # key ?
		
		

if __name__ == "__main__": #to be removed in final
    mainLoopCounter()
