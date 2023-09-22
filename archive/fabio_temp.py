#@authors Fabio Schmidt
#@last change XX.08.2023                                                                            // anpassen vor Abgabe
#@description: A temporary file to write code.


# Useful references:
# 	Ghidra API: https://ghidra.re/ghidra_docs/api/allclasses.html
#	Ghidra Snippets: https://github.com/HackOvert/GhidraSnippets/tree/master


# zu beachten: Nicht überspezialisieren! Immer wieder testen und dann geg. ausarbeiten!

#################################################################################################################################
# Notizen hier anmerken:

# python interpreter öffnen: window --> python





#################################################################################################################################

# Findung der KSA und PRGA Methoden (idee)

# if (0x100 || && (paramcount >= 3 && <=4) && isConditionalCount = 2 w/ JMP or CMP){
#   is a KSA function 
# }
#
# if (0x100 || && paramcount >= 3 && isConditionalCount = 1 w/ XOR){
#   is a PRGA function
# }
#
#


# Boolean Check in the end for both funtions separately (table):
#
# Function      Has Constant 0x100      Has Paramcount      Has X Loops
# ---------------------------------------------------------------------       
# fun_13245     true                    true                true
# fun_88221     false                   false               true
# ...
#



#################################################################################################################################


# Gemeinsamkeiten KSA:
  #1. Konstante 0x100
  #2. (Initialisierung der S-Box (Array) mit einer Konstante (0x100))
  #3. S-Box meist als Bytearray initialisiert.
  #4. Doppelte Schleife
  #5. Parameter der Funktion (int *arg_sbox,int *arg_key,uint arg_key_len)
    
  
# Gemeinsamkeiten PRGA:
  #1. Konstante 0x100
  #2. Einzelne Schleife (mit XOR-Operator am Ende)
  #3. Parameter der Funktion (int arg_sbox,int arg_sbox_len,int arg_data_len,byte *arg_data)


#################################################################################################################################

#imports

??





#################################################################################################################################





#Goes trough functions and prints function informations to the console
fm = currentProgram.getFunctionManager()
functions = fm.getFunctions(True)
# walk over all functions
content = ""
for f in functions:
	content += "{}: 0x{:x}\n".format(f.name, f.getEntryPoint().getOffset())
print(content)


# what is a select function?
# Print all instructions in a select function
from binascii import hexlify

listing = currentProgram.getListing()
main_func = getGlobalFunctions("main")[0] # assume there's only 1 function named 'main'
addrSet = main_func.getBody()
codeUnits = listing.getCodeUnits(addrSet, True) # true means 'forward'

for codeUnit in codeUnits:
	print("0x{} : {:16} {}".format(codeUnit.getAddress(), hexlify(codeUnit.getBytes()), codeUnit.toString()))




#################################################################################################################################

# Find 0x100 Constant

# ref: https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html#findBytes(ghidra.program.model.address.Address,java.lang.String,int,int)


# Same methods also in Python!

    findBytes

    public final Address findBytes​(Address start, java.lang.String byteString)

    Finds the first occurrence of the byte array sequence that matches the given byte string, starting from the address. If the start address is null, then the find will start from the minimum address of the program.

    The byteString may contain regular expressions. The following highlights some example search strings (note the use of double backslashes ("\\")):

                 "\\x80" - A basic search pattern for a byte value of 0x80
     "\\x50.{0,10}\\x55" - A regular expression string that searches for the byte 0x50
                           followed by 0-10 occurrences of any byte value, followed
                           by the byte 0x55
     

    Parameters:
        start - the address to start searching. If null, then the start of the program will be used.
        byteString - the byte pattern for which to search
    Returns:
        the first address where the byte was found, or null if the bytes were not found
    Throws:
        java.lang.IllegalArgumentException - if the byteString is not a valid regular expression
    See Also:
        findBytes(Address, String, int)


## own code

findBytes(currentAddress,"\\100") --> no error
# Console: works, current adress has no 0x100 value :)
>>> print(findBytes(currentAddress,"\\100"))
None



# putting it all together:
# going trough all functions, addresses and look for the 0x100 value


import ghidra.app.script.GhidraScript


func = getFirstFunction()
while func is not None:
	addr = currentProgram.getMinAddress()
    # print()
	while addr is not None:    
		if findBytes(currentAddress,"\\100"):
        		print("Hit at " + str(addr) + " in function " + str(func) + '\n') # only for testing, array in further usage
		addr = addr.next()
        # print()
    func = getFunctionAfter(func)

#   --> still endless loop
# --> pro Block allenfalls machen / Working with Instructions Python / P-Code nutzen

# allenfalls das:

# Print all instructions in a select function
# Just like objdump or a disas command in GDB, Ghidra provides a way to dump instructions if you need.
# You might do this to generate input for another application, or for documenting issues
# found during analysis. Whatever you use case might be, you can easily acquire the address, opcodes, and instruction text for a target function, or specific addresses.

from binascii import hexlify

listing = currentProgram.getListing()
main_func = getGlobalFunctions("main")[0] # assume there's only 1 function named 'main'
addrSet = main_func.getBody()
codeUnits = listing.getCodeUnits(addrSet, True) # true means 'forward'

for codeUnit in codeUnits:
	print("0x{} : {:16} {}".format(codeUnit.getAddress(), hexlify(codeUnit.getBytes()), codeUnit.toString()))


# does not work, trying to finding another way



# works but very slow
listing = currentProgram.getListing()

func = getFirstFunction()
while func is not None:
	addr = currentProgram.getMinAddress()
	while addr is not None:    
		# codeUnits = listing.getCodeUnits(addr, True) # printing per adress
		instr = listing.getInstructionAt(addr)
		print(str(func) + '\t' + str(addr) + '\t' + str(instr))
		addr = addr.next()
	func = getFunctionAfter(func)



# new way with codeunits

from binascii import hexlify

# codeUnits = listing.getCodeUnits(addrSet, True)

# for instr in currentProgram.getListing().getInstructions(True):
    # print(instr)

# for codeUnit in codeUnits:
	# print("0x{} : {:16} {}".format(codeUnit.getAddress(), hexlify(codeUnit.getBytes()), codeUnit.toString()))


# test: KSA function range from mem 004018eb to 0040199c
listing = currentProgram.getListing()

func = getFirstFunction()
while func is not None:
	addr = currentProgram.getMinAddress()
	while addr is not None:    
		codeUnits = listing.getCodeUnits(addr, True) # printing per adress
		
		for codeUnit in codeUnits:
			print str(func) + '\t' + ("0x{} : {:16} {}".format(codeUnit.getAddress(), hexlify(codeUnit.getBytes()), codeUnit.toString()))
		#instr = listing.getInstructionAt(addr)
		#print(str(func) + '\t' + str(addr) + '\t' + str(instr))
		addr = addr.next()
	func = getFunctionAfter(func)

















#################################################################################################################################

# Find (number) of parameter per function
# ref: https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getParameterCount()

int getParameterCount()

Gets the total number of parameters for this function. This number also includes any auto-parameters which may have been injected when dynamic parameter storage is used.

Returns:
    the total number of parameters 


# Get parameters of function

# ref: https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html#getParameters()

    getParameters

    Parameter[] getParameters()

    Get all function parameters

    Returns:
        all function parameters



# Analyzing function call arguments
# This snippet uses a TARGET_ADDR which should be the address of a call to return the call arguments at that address. Thanks to gipi for suggesting this much cleaner way to obtain function call arguments than previously listed!
# ref:https://github.com/HackOvert/GhidraSnippets#analyzing-function-call-arguments

from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# # Disassembly shows: 00434f6c    CALL    FUN_00433ff0
# # Decompiler shows:  uVar1 = FUN_00433ff0(param_1,param_2,param_3);
TARGET_ADDR = toAddr(0x00434f6c)

options = DecompileOptions()
monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.setOptions(options)
ifc.openProgram(currentProgram)

func = getFunctionContaining(TARGET_ADDR)
res = ifc.decompileFunction(func, 60, monitor)
high_func = res.getHighFunction()
pcodeops = high_func.getPcodeOps(TARGET_ADDR)
op = pcodeops.next()
print(op.getInputs())


## Returns Function name and amount of parameters per function
# ref: https://github.com/NationalSecurityAgency/ghidra/issues/1984
fiter = currentProgram.getFunctionManager().getFunctions(True)
while (fiter.hasNext()):
	function = fiter.next()
	if (monitor.isCancelled()):         # kein schimmer
		break
	print str(function.getName()) + ":" + str(function.getParameterCount()) + "\n"



#################################################################################################################################


# Finding the loops
# Print all instructions in a select function
# Just like objdump or a disas command in GDB, Ghidra provides a way to dump instructions if you need. You might do this to generate input for another application, or for documenting issues   found during analysis. Whatever you use case might be, you can easily acquire the address, opcodes, and instruction text for a target function, or specific addresses.
# ref: https://github.com/HackOvert/GhidraSnippets#print-all-instructions-in-a-select-function


# Idee: folgender Code als Startpunkt nehmen und explizit die "CMP" oder "JZ" (etc) Instruktionen ausfindig machen

from binascii import hexlify

listing = currentProgram.getListing()
main_func = getGlobalFunctions("main")[0] # assume there's only 1 function named 'main'
addrSet = main_func.getBody()
codeUnits = listing.getCodeUnits(addrSet, True) # true means 'forward'

for codeUnit in codeUnits:
	print("0x{} : {:16} {}".format(codeUnit.getAddress(), hexlify(codeUnit.getBytes()), codeUnit.toString()))



# Get the flow type of this instruction (how this instruction flows to the next instruction).
# ref: https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html#getFlowType()


getFlowType

FlowType getFlowType()

Get the flow type of this instruction (how this instruction flows to the next instruction).

# other method from same Class FlowType
#Returns true if the flow is a conditional call or jump
boolean 	isConditional()






# own code

# ideal would be to automate the function under "search->Program Text->Select Fields->Instruction Mnemonics", Search Regex "XOR(.*),\1"

# return Mnemonic and function it was found in
# ref: https://reverseengineering.stackexchange.com/questions/26724/how-do-i-get-the-all-the-basic-binary-blocks-containing-a-special-instruction-li


functions = currentProgram.getFunctionManager().getFunctions(True)
for function in functions:
    cur = function.getEntryPoint()
    while cur:
        inst = getInstructionAt(cur)
        if inst:
            # add similar check for call instruction
            if "CMP" in inst.getMnemonicString():
                #do something
                print (str(inst) + " found in " + str(function))
                # this will break when function returns
                break
        cur = cur.next()


## funktioniert und dann bleibt es stehen. Endlos for-schleife?




# also: idea is to find two loops, so this should return a statistic with the functions name and the amounts of "CMP" it contains


# Headers: CMP / JP / Function
# Values: int / int / String
# ref: https://www.youtube.com/watch?v=Smf68icE_as
#table:
table_data = [  ['CMP', 'JP', 'Function'],
                ['val', 'val2', 'func']
                ]


for row in table_data:
    for col in row:
        print(col, end=' ')
    print()


# or with tabulate

from tabulate import tabulate

table_data = [...]

print(tabulate(table_data, headers="firstrow")) # uses first row as header





#---------->> current

from __future__ import print_function  # Python2 print was a statement, Python3 it's a function.
import ghidra.app.script.GhidraScript


functions = currentProgram.getFunctionManager().getFunctions(True)
for function in functions:
    cur = function.getEntryPoint()
    while cur:
        inst = getInstructionAt(cur)
        if inst:
            if "CMP" in inst.getMnemonicString():
                #add entries to table
                #print (str(inst) + " found in " + str(function))
		table_data = []
		table_data.append(function)
		table_data.append(inst)                
		# this will break when function returns
                break
        cur = cur.next()




#   Function    Instruction
#   -----------------------
#   FUN_1235    3
#   FUN_6234    6
#   ...
# print function names only once and order them with the number of compares
# table_data.count(X), ref: https://www.programiz.com/python-programming/methods/list/count



# print statistics
print("Function" + '\t' + "CMP")
for row in table_data:
    for col in row:
        print(col, end = '\t')
    print()




# alternativ:  	loopDegree​(Vertex v) 	Returns numLoops as a double. ref: https://ghidra.re/ghidra_docs/api/ghidra/util/graph/DirectedGraph.html
# alternativ: refined p code, while bzw. for suchen






#################################################################################################################################

# S-box initialised as a (byte) array


# dumping raw pcode vs refined code ??


# Dumping Raw PCode
def dump_raw_pcode(func):
    func_body = func.getBody()
    listing = currentProgram.getListing()
    opiter = listing.getInstructions(func_body, True)
    while opiter.hasNext():
        op = opiter.next()
        raw_pcode = op.getPcode()
        print("{}".format(op))
        for entry in raw_pcode:
            print("  {}".format(entry))

func = getGlobalFunctions("main")[0]    # assumes only one function named `main`
dump_raw_pcode(func)            	    # dump raw pcode as strings



