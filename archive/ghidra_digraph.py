from ghidra.util.graph import DirectedGraph
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

#prep
digraph = DirectedGraph()
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

funcs = fm.getFunctions(True) # True mean iterate forward
for func in funcs: 
	# Add function vertices
	print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint())) # FunctionDB
	digraph.add(Vertex(func))

# Add edges for static calls
	entryPoint = func.getEntryPoint() 							# start of the edge is function start
	instructions = listing.getInstructions(entryPoint, True)	# get all instr.
	for instruction in instructions:
        addr = instruction.getAddress()                         # the issue lies here, unknown why
		# print(addr)                                           # for testing, it does seem to work for a while
        oper = instruction.getMnemonicString()
		if oper == "CALL":
			print("    0x{} : {}".format(addr, instruction))    # format() formats specified value(s) and inserts them inside the placeholder
			flows = instruction.getFlows()                      # getFlows(): Get an array of Address objects for all flows other than a fall-through
            if len(flows) == 1:
                target_addr = "0x{}".format(flows[0])
                digraph.add(Edge(Vertex(func), Vertex(fm.getFunctionAt(getAddress(target_addr)))))
        

print("DiGraph info:")
edges = digraph.edgeIterator()
while edges.hasNext():
	edge = edges.next()
	from_vertex = edge.from()
	to_vertex = edge.to()
	print("  Edge from {} to {}".format(from_vertex, to_vertex))

vertices = digraph.vertexIterator()
while vertices.hasNext():
	vertex = vertices.next()
	print("  Vertex: {} (key: {})".format(vertex, vertex.key()))
