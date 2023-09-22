def count_parameter(function):
	parameter_count = 0
	for parameter in function.getParameters():
		parameter_count += 1
	return parameter_count



def searchValue(codeUnits):

	for codeUnit in codeUnits:
        	codeUnitString = codeUnit.toString()
		if '0x100' in codeUnitString:
        		return True
    	return False

def main():
	listing = currentProgram.getListing()
	functions = listing.getFunctions(True)
	
	for func in functions:
		addrSet = func.getBody()
		codeUnits = listing.getCodeUnits(addrSet, True)
		valueBoolean = searchValue(codeUnits)
		
		if (count_parameter(func) >= 3):
			print(func.getName(), func.getEntryPoint(), valueBoolean)
		

if __name__ == "__main__":
    main()
