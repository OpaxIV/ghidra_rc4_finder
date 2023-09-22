#@authors Jonas Eggenberg
#@last change XX.08.2023                                                                            // anpassen vor Abgabe
#@description: A temporary file to write code.

# ha 3 dateie gmacht: 1 för de fertig code, denn na jewiils eini för dich und mich zum chli umeprobiere.
# wenn mer de eppis gschids zum implementiere hend, chemmers denn zeme aluege und denn id hauptdatei verschiebe
######################################################################################################
#Master Main function that calls all the subfunctions

def main():
	mainParamteterCounter();
	mainHexValueCheck();
	mainLoopCount();

if __name__ == "__main__":
    main()


######################################################################################################
#ParameterCounter
#description: prints the Name of the function, address and the parametercount
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

if __name__ == "__main__":
    mainParameterCounter()



##################################################################################################################

  #HexValueCheck
  #description: prints the Name of the function, address and the boolean true if 0x100 was found/false if not
    
 
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
		if('RC4' in func.getName()): #if to be removed in final. only for testing
			print(func.getName(), func.getEntryPoint(), valueBoolean)
		

if __name__ == "__main__":
    mainHexValueCheck()


###################################################################################################################

#Find Loops in function
#description: prints the Name of the function, address and/and how many loops where found



