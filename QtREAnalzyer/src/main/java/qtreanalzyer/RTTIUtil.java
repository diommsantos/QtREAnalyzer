package qtreanalzyer;

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class RTTIUtil{
	
	//Checks whether the C++ class gClass has virtual functions
	static boolean hasRTTI(GhidraClass gClass) {
		SymbolTable symbolTable = gClass.getSymbol().getProgram().getSymbolTable();
		SymbolIterator classSymbolsIt = symbolTable.getSymbols(gClass);
		while(classSymbolsIt.hasNext()) {
			if(classSymbolsIt.next().getName().startsWith("RTTI"))
				return true;
		}
		return false;
	}
	
	//Checks whether the C++ class derived inherits the C++ class base
	static boolean inherits(GhidraClass derived, String base) {
		if(!hasRTTI(derived))
			return false;
		SymbolTable symbolTable = derived.getSymbol().getProgram().getSymbolTable();
		List<Symbol> rttiBCArray  = symbolTable.getSymbols("RTTI_Base_Class_Array", derived);
		if(rttiBCArray.size() == 0)
			return false;
		Data data = derived.getSymbol().getProgram().getListing().getDataAt(
				rttiBCArray.get(0).getAddress());
		for(int i = 0; i < data.getNumComponents(); i++) {
			Reference references[] = data.getComponent(i).getOperandReferences(0);
			if(symbolTable.getSymbols(references[0].getToAddress())[0]
			   .getName(true).startsWith(base))
				return true;
		}
		return false;
	}
	
	static Address getStaticMetaObjectAddress(GhidraClass gClass, Program program) {
		SymbolTable symbolTable = program.getSymbolTable();
		List<Symbol> vftables  = symbolTable.getSymbols("vftable", gClass);
		if(vftables.size() == 0)
			return null;
		Data vftableData = program.getListing().getDataAt(vftables.get(0).getAddress());
		Reference references[] = vftableData.getComponent(0).getOperandReferences(0);
		Function metaObjectF = program.getFunctionManager().getFunctionAt(references[0].getToAddress());
		InstructionIterator instructions = program.getListing().getInstructions(metaObjectF.getBody(), true);
		while(instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if(instruction.getMnemonicString().equals("LEA")) {
				references = instruction.getOperandReferences(1);
				return references[0].getToAddress();
			}
		}
		return null;
	}
}
