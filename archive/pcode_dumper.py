# imports
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex
#from ghidra.program.model.pcode import PcodeOp, PcodeOpAST, PcodeSyntaxTree

# == helper functions =============================================================================
def get_high_function(func):
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    # Setting a simplification style will strip useful `indirect` information.
    # Please don't use this unless you know why you're using it.
    #ifc.setSimplificationStyle("normalize") 
    res = ifc.decompileFunction(func, 60, monitor)
    high = res.getHighFunction()
    return high

def dump_refined_pcode(func, high_func):
    opiter = high_func.getPcodeOps()
    while opiter.hasNext():
        op = opiter.next()
        print("{}".format(op.toString()))
        
# == run examples =================================================================================


if __name__ == "__main__":
    blockModel = BasicBlockModel(currentProgram)
    listing = currentProgram.getListing()		
    
    fm = currentProgram.getFunctionManager()					# needed for managing functions of program
    funcs = fm.getFunctions(True)	
    
    for func in funcs:
        hf = get_high_function(func)            # we need a high function from the decompiler
        dump_refined_pcode(func, hf)            # dump straight refined pcode as strings
