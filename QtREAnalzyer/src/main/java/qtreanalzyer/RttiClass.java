package qtreanalzyer;

import java.util.List;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Represents a C++ class that contains Run Time Type Information. 
 * Users of this class should check if it contains Run Time Type Information with {@link #hasRtti()} 
 * before invoking other methods.
 */

public class RttiClass implements GhidraClass {
	
	GhidraClass ghidraClass;
	protected Program program;
	protected SymbolTable symbolTable;
	protected Listing listing;
	
	boolean rttiClass = false;
	
	RttiClass(GhidraClass ghidraClass){
		this.ghidraClass = ghidraClass;
		this.program = ghidraClass.getSymbol().getProgram();
		this.symbolTable = program.getSymbolTable();
		this.listing = program.getListing();
		this.rttiClass = checkRtti();
	}
	
	/**
	 * Checks whether this namespace contains the typical MSVC RTTI structs. 
	 * See <a href=https://www.lukaszlipski.dev/post/rtti-msvc/>https://www.lukaszlipski.dev/post/rtti-msvc/</a> 
	 * for more details.
	 * @return true if this class has RTTI type information
	 */
	private boolean checkRtti() {
		SymbolIterator classSymbolIterator = symbolTable.getSymbols(ghidraClass);
		while(classSymbolIterator.hasNext()) {
			if(classSymbolIterator.next().getName().startsWith("RTTI"))
				return true;
		}
		return false;
	}
	
	/**
	 * @return true if this class has RTTI type information
	 */
	public boolean hasRtti() {
		return rttiClass;
	}
	
	/**
	 * Checks if the C++ class {@link RttiClass} represents inherits {@link ghidraBaseClass}
	 * For example if we have the following C++ class definitions: <br>
	 * <br>
	 * class A {} <br>
	 * 
	 * class B: public A {} <br>
	 * <br>
	 * and the RttiClass object bRttiClass represents the C++ B class, bRttiClass.inherits("A") returns true. <br>
	 * NOTE: This method returns false if given the name of the C++ class it represents.
	 * @param ghidraBaseClass C++ class name to check for inheritance
	 * @return true if the C++ class {@link RttiClass} represents inherits {@link ghidraBaseClass}
	 */
	public boolean inherits(String ghidraBaseClass) {
		List<Symbol> baseClassArraySymbols  = symbolTable.getSymbols("RTTI_Base_Class_Array", ghidraClass);
		if(baseClassArraySymbols.size() == 0)
			return false;
		Data baseClassArrayData = listing.getDataAt(baseClassArraySymbols.get(0).getAddress());
		for(int i = 1; i < baseClassArrayData.getNumComponents(); i++) {
			Reference baseClassArrayReference = baseClassArrayData.getComponent(i).getOperandReferences(0)[0];
			String baseClassName = symbolTable.getSymbols(baseClassArrayReference.getToAddress())[0].getName(true); 
			if(baseClassName.startsWith(ghidraBaseClass))
				return true;
		}
		return false;
		
	}
	
	@Override
	public Symbol getSymbol() {
		return ghidraClass.getSymbol();
	}

	@Override
	public boolean isExternal() {
		return ghidraClass.isExternal();
	}

	@Override
	public String getName() {
		return ghidraClass.getName();
	}

	@Override
	public String getName(boolean includeNamespacePath) {
		return ghidraClass.getName(includeNamespacePath);
	}

	@Override
	public long getID() {
		return ghidraClass.getID();
	}

	@Override
	public Namespace getParentNamespace() {
		return ghidraClass.getParentNamespace();
	}

	@Override
	public AddressSetView getBody() {
		return ghidraClass.getBody();
	}

	@Override
	public void setParentNamespace(Namespace parentNamespace)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		ghidraClass.setParentNamespace(parentNamespace);
	}

}
