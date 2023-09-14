# Authors: Fabio Schmidt, Jonas Eggenberg
# Assisted by the Tutor: Tim Blazytko
# Date: XX.YY.ZZZZ
# Version: final

# Python Script used for finding potential RC4 implementations in programs.
# Uses the ghidra API as a basis



######################################################################################################
# Find Functions with hex value 0x100
# Description: Prints every function and returns true/false if the hex number is present in said function

def searchValue(codeUnits):
	for codeUnit in codeUnits:
        codeUnitString = codeUnit.toString()
        if '0x100' in codeUnitString:
            return True
        return False

def mainHexValueCheck():
	listing = currentProgram.getListing()
	functions = listing.getFunctions(True)
	
	for func in functions:
		addrSet = func.getBody()
		codeUnits = listing.getCodeUnits(addrSet, True)
		valueBoolean = searchValue(codeUnits)
		#if('RC4' in func.getName()): #if to be removed in final. only for testing
		print(func.getName(), func.getEntryPoint(), valueBoolean)
		



######################################################################################################
# Counts the parameters of function(s)
# Description: prints the Name of the function, address and the parametercount
def count_parameter(function):
	parameter_count = 0
	for parameter in function.getParameters():
		parameter_count += 1
	return parameter_count
	
def mainParameterCounter():
	func=getFirstFunction()
	while func is not None:
		parameter_count = count_parameter(func)
		print(func.getName(), func.getEntryPoint(), parameter_count)
		func = getFunctionAfter(func)




######################################################################################################
# loopCounter
# Description: Counts the loops of functions


######################################################################################################


if __name__ == "__main__":
		mainParameterCounter()
		mainHexValueCheck()
