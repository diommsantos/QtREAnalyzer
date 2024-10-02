package qtreanalzyer;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.app.util.importer.MessageLog;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeFrame;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import qtreanalzyer.QtMetaDataData.QtMetaDataMethodInfo;
import qtreanalzyer.QtMetaDataData.QtMetaDataPropertie;

public class QtClassSolver {
	
	MessageLog log;
	QtClass qtClass;
	Program program;
	Memory memory;
	Listing listing;
	SymbolTable symbolTable;
	FunctionManager functionManager;
	DataTypeManager dataTypeManager;
	QtTypesManager qtTypesManager;
	
	EnumDataType qMetaTypeTypes;
	
	public QtClassSolver(QtClass ghidraClass) {
		this.log = QtREAnalzyerAnalyzer.getMessageLog();
		this.qtClass = ghidraClass;
		this.program = ghidraClass.getSymbol().getProgram();
		this.memory = program.getMemory();
		this.listing = program.getListing();
		this.symbolTable = program.getSymbolTable();
		this.functionManager = program.getFunctionManager();
		this.dataTypeManager = program.getDataTypeManager();
		this.qtTypesManager = QtTypesManager.getQtTypesManager(qtClass);
		this.qMetaTypeTypes = qtTypesManager.getQMetaTypeTypes();
	}
	
	
	
	public Data solveQMetaObject() {		
			try {
				Address staticMetaObjectAddress = getStaticMetaObjectAddress();
				
				symbolTable.createLabel(staticMetaObjectAddress, 
										"staticMetaObject", 
										qtClass, 
										SourceType.ANALYSIS);
				
				DataType qMetaObject = qtTypesManager.getQMetaObject();
				listing.clearCodeUnits(staticMetaObjectAddress, 
									   staticMetaObjectAddress.add(qMetaObject.getAlignedLength() - 1), 
									   false);
				return listing.createData(staticMetaObjectAddress, qMetaObject);
			} catch (RuntimeException | InvalidInputException | CodeUnitInsertionException e) {
				log.appendMsg("QtClassSolver: It was not possible to solve staticMetaObject for the " +
							  qtClass.getName()+" class.");
				return null;
			}
	}
	
	private Address getStaticMetaObjectAddress() {
		List<Symbol> vftables  = symbolTable.getSymbols("vftable", qtClass);
		if(vftables.size() == 0)
			return null;
		Data vftableData = listing.getDataAt(vftables.get(0).getAddress());
		Reference reference = vftableData.getComponent(0).getOperandReferences(0)[0];
		Function metaObject = functionManager.getFunctionAt(reference.getToAddress());
		InstructionIterator instructions = listing.getInstructions(metaObject.getBody(), true);
		while(instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if(instruction.getMnemonicString().equals("LEA")) {
				reference = instruction.getOperandReferences(1)[0];
				return reference.getToAddress();
			}
		}
		return null;
	}
	
	public Data solveQtMetaStringdata() {
		if(qtClass.getQMetaObjectData() == null)
			return null;
		try {
			Address address = qtClass.getQMetaObjectData().getStringdata();
			symbolTable.createLabel(address, "qt_meta_stringdata_"+qtClass.getName(), qtClass, SourceType.ANALYSIS);
			DataType qtMetaStringdata = getQtMetaStringdata(address);
			listing.clearCodeUnits(address, address.add(qtMetaStringdata.getAlignedLength() - 1), false);
			return listing.createData(address, qtMetaStringdata);
		} catch (RuntimeException | InvalidInputException | MemoryAccessException | CodeUnitInsertionException e) {
			log.appendMsg("QtClassSolver: It was not possible to solve qt_meta_stringdata_" + qtClass.getName() +
					" for the " + qtClass.getName() + " class.");
			return null;
		}
	}
	
	public DataType getQtMetaStringdata(Address qtMetaStringdataAddress) throws MemoryAccessException {
		DataType intDataType = program.getDataTypeManager().getDataType("/int");
		int intLenght = intDataType.getLength();
		
		Address strdata0IndexAddr = qtMetaStringdataAddress.add(intLenght * 4);
		long stringdata0Index = memory.getLong(strdata0IndexAddr);
		
		DataType qByteArrayData = qtTypesManager.getQByteArrayData();
		int numDataEntries = (int) stringdata0Index / qByteArrayData.getAlignedLength();
		
		Structure qtMetaStringdata = qtTypesManager.newStruct("qt_meta_stringdata_"+qtClass.getName()+"_t");
		
		ArrayDataType data = new ArrayDataType(qByteArrayData, numDataEntries);
		
		DataType charType = dataTypeManager.getDataType("/char");
		Structure stringdata = qtTypesManager.newStruct("stringdata");
		for(int i = 0; i < numDataEntries; i++) {
			int stringdataiLenght = memory.getInt(qtMetaStringdataAddress.add(qByteArrayData.getAlignedLength() * i + intLenght * 1));
			stringdata.add(new ArrayDataType(charType, stringdataiLenght+1), "stringdata"+i, null);
		}
		
		qtMetaStringdata.add(data, "data", null);
		qtMetaStringdata.add(stringdata, "stringdata", null);
		qtMetaStringdata.setToDefaultPacking();
		
		return qtMetaStringdata;
	}
	
	public Data solveQtMetaData() {
		if(qtClass.getQMetaObjectData() == null)
			return null;
		try {
			Address address = qtClass.getQMetaObjectData().getQtData();
			symbolTable.createLabel(address, "qt_meta_data_"+qtClass.getName(), qtClass, SourceType.ANALYSIS);
			
			DataType qtMetaDataType = getQtMetaData(address);
			listing.clearCodeUnits(address, address.add(qtMetaDataType.getAlignedLength() - 1), false);
			return listing.createData(address, qtMetaDataType);
		} catch(RuntimeException | MemoryAccessException | InvalidInputException | CodeUnitInsertionException e) {
			log.appendMsg("QtClassSolver: It was not possible to solve qt_meta_data_" + qtClass.getName() +
					" for the " + qtClass.getName() + " class.");
			return null;
		}
	}
	
	public DataType getQtMetaData(Address qtMetaDataAddress) throws MemoryAccessException, AddressOutOfBoundsException {
		DataType intDataType = dataTypeManager.getDataType("/int");
		int intLenght = intDataType.getLength();
		Structure qtMetaDataType = qtTypesManager.newStruct("qt_meta_data_"+qtClass.getName());
		qtMetaDataType.add(intDataType, "revision", null);
		qtMetaDataType.add(intDataType, "classname", null);
		qtMetaDataType.add(intDataType, "classinfo_count", null);qtMetaDataType.add(intDataType, "classinfo_index", null);
		qtMetaDataType.add(intDataType, "methods_count", null);qtMetaDataType.add(intDataType, "mehtods_index", null);
		qtMetaDataType.add(intDataType, "properties_count", null);qtMetaDataType.add(intDataType, "properties_index", null);
		qtMetaDataType.add(intDataType, "enum_sets_count", null);qtMetaDataType.add(intDataType, "enums_sets_index", null);
		qtMetaDataType.add(intDataType, "constructors_count", null);qtMetaDataType.add(intDataType, "constructors_index", null);
		qtMetaDataType.add(intDataType, "flags", null);
		qtMetaDataType.add(intDataType, "signalCount", null);
		
		int methodsCount = memory.getInt(qtMetaDataAddress.add(intLenght * 4));
		int methodsIndex = memory.getInt(qtMetaDataAddress.add(intLenght * 5));
		int propertiesCount = memory.getInt(qtMetaDataAddress.add(intLenght * 6));
		int propertiesIndex = memory.getInt(qtMetaDataAddress.add(intLenght * 7));
		
		Structure qtMetaDataMethodDT = qtTypesManager.newStruct("qt_meta_data_method");
		qtMetaDataMethodDT.add(intDataType, "name", null);
		qtMetaDataMethodDT.add(intDataType, "argc", null);
		qtMetaDataMethodDT.add(intDataType, "parameters", null);
		qtMetaDataMethodDT.add(intDataType, "tag", null);
		qtMetaDataMethodDT.add(intDataType, "flags", null);
		
		if(methodsCount > 0)
			qtMetaDataType.insertAtOffset(intLenght*methodsIndex, 
				new ArrayDataType(qtMetaDataMethodDT, methodsCount), 0);
		
		//constructs the method parameters
		Structure qtMetaDataParamsDT = qtTypesManager.newStruct("qt_meta_data_parameters");
		int parameters0 = memory.getInt(qtMetaDataAddress.add(intLenght*(methodsIndex+2)));
		for(int i = 0; i < methodsCount; i++) {
			int argc = memory.getInt(qtMetaDataAddress.add(intLenght*(methodsIndex+1+i*5)));
			int parameters = memory.getInt(qtMetaDataAddress.add(intLenght*(methodsIndex+2+i*5)));
			int relativeIndex = parameters-parameters0;
			
			//construct qt_meta_data_parameters DataType
			Structure qtMetaDataParamDT = qtTypesManager.newStruct("qt_meta_data_parameters"+i);
			qtMetaDataParamDT.add(intDataType, "return", null);
			for(int j = 0; j < argc; j++)
				qtMetaDataParamDT.add(intDataType, "parameter"+j, null);
			for(int j = 0; j < argc; j++)
				qtMetaDataParamDT.add(intDataType, "parameter_index"+j, null);
			
			qtMetaDataParamsDT.insertAtOffset(intLenght * relativeIndex, qtMetaDataParamDT, 
					0, "qt_meta_data_parameters"+i, null);
		}
		
		if(methodsCount > 0)
			qtMetaDataType.insertAtOffset(intLenght * parameters0, qtMetaDataParamsDT, 0);
		
		Structure qtMetaDataPropsDT = qtTypesManager.newStruct("qt_meta_data_properties");
		qtMetaDataPropsDT.add(intDataType, "name", null);
		qtMetaDataPropsDT.add(intDataType, "type", null);
		qtMetaDataPropsDT.add(intDataType, "flags", null);
		
		if(propertiesCount > 0)
			qtMetaDataType.insertAtOffset(intLenght*propertiesIndex, new ArrayDataType(qtMetaDataPropsDT, propertiesCount), 0);
		
		return qtMetaDataType;
	}
	
	public Function solveQtStaticMetacall() {
		if(qtClass.getQMetaObjectData() == null)
			return null;
		try {
			Address adress = qtClass.getQMetaObjectData().getQtStatic_metacall();
			Function qtStaticMetacall = functionManager.getFunctionAt(adress);
			
			if(!qtStaticMetacall.getName().equals("qt_static_metacall"))
				qtStaticMetacall.setName("qt_static_metacall", SourceType.ANALYSIS);
			if(!(qtStaticMetacall.getParentNamespace().getID() == qtClass.getID()))
				qtStaticMetacall.setParentNamespace(qtClass);
			
			qtStaticMetacall.setCallingConvention("__fastcall");
			
			DataType voidType = dataTypeManager.getDataType("/void");
			qtStaticMetacall.setReturnType(voidType, SourceType.ANALYSIS);
			
			ParameterImpl _o = new ParameterImpl("_o", dataTypeManager.getDataType("/void *"), program, SourceType.ANALYSIS);
			
			ParameterImpl _c = new ParameterImpl("_c", dataTypeManager.getDataType("/int"), program, SourceType.ANALYSIS);
			
			ParameterImpl _id = new ParameterImpl("_id", dataTypeManager.getDataType("/int"), program, SourceType.ANALYSIS);
			
			DataType voidPtrPtrType = new PointerDataType(new PointerDataType(dataTypeManager.getDataType("/void")));
			ParameterImpl _a = new ParameterImpl("_a", voidPtrPtrType, program, SourceType.ANALYSIS);
			
			qtStaticMetacall.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, 
											   SourceType.ANALYSIS, _o, _c, _id, _a);
			return qtStaticMetacall;
		} catch(RuntimeException | InvalidInputException | DuplicateNameException | CircularDependencyException e) {
			log.appendMsg("QtClassSolver: It was not possible to solve qt_static_metacall"+
					" for the " + qtClass.getName() + " class.");
			return null;
		}
	}
	
	public void annotateQtStaticMetacall() {
		if(qtClass.getQMetaObjectData() == null || qtClass.getQtStaticMetacall() == null)
			return;
		try {
			int methodsCount = qtClass.getQtMetaDataData().getQtMethodsCount();
			String comment = "Methods:\n";
			for(int i = 0; i < methodsCount; i++) {
				comment +=  i + "- " + getMethodSignature(i) + "\n";
			}
			
			comment += "\n";
			
			int propertiesCount = qtClass.getQtMetaDataData().getQtPropertiesCount();
			comment += "Properties:\n";
			for(int i = 0; i< propertiesCount; i++) {
				comment +=  i + "- " + getPropertieSignature(i) + "\n";
			}
			
			Address adress = qtClass.getQtStaticMetacall().getEntryPoint();
			listing.setComment(adress, CodeUnit.PLATE_COMMENT, comment);
			
			return;
		} catch (RuntimeException e) {
			log.appendMsg("QtClassSolver: It was not possible to annotate qt_static_metacall"+
					" for the " + qtClass.getName() + " class.");
			return;
		}
	}
	
	private String getMethodSignature(int index) {
		QtMetaDataMethodInfo methodInfo = qtClass.getQtMetaDataData().getQtMetaDataMethodInfo(index);
		QtMetaStringdataData stringdata = qtClass.getQtMetaStringdataData();
		
		String signature = "";
		
		int returnType = methodInfo.params().qtReturn(); 
		signature += getQtMetaDataTypeString(returnType) + " ";
		
		int methodName = methodInfo.method().qtName();
		signature += stringdata.getQtStringdata(methodName);
		
		signature += "(";
		int numParams = methodInfo.method().qtArgc();
		for(int i = 0; i < numParams; i++) {
			int paramType = methodInfo.params().qtParameters()[i];
			signature += getQtMetaDataTypeString(paramType) + " ";
			
			int paramName = methodInfo.params().qtParametersIndex()[i];
			signature += stringdata.getQtStringdata(paramName)+", ";
		}
		signature = numParams > 0 ? signature.substring(0, signature.length()-2) + ")" : signature + ")";
		
		return signature;
	}
	
	private String getPropertieSignature(int index) {
		QtMetaDataPropertie propertie = qtClass.getQtMetaDataData().getQtMetaDataPropertie(index);
		QtMetaStringdataData stringdata = qtClass.getQtMetaStringdataData();
		
		String signature = "";
		
		int propertieType = propertie.qtType();
		signature += getQtMetaDataTypeString(propertieType) + " ";
		
		int propertieName = propertie.qtName();
		signature += stringdata.getQtStringdata(propertieName);
		
		return signature;
	}
	
	private String getQtMetaDataTypeString(int type) {
		if(qMetaTypeTypes.contains(type))
			return qMetaTypeTypes.getName(type);
		if((type & 0x80000000) == 0x80000000)
			return qtClass.getQtMetaStringdataData().getQtStringdata(type ^ 0x80000000);
		return "unknown";
	}
	
	public Function[] solveQtMethods() {
		if(qtClass.getQMetaObjectData() == null || qtClass.getQtStaticMetacall() == null)
			return null;
		
		QtMetaDataData qtData = qtClass.getQtMetaDataData();
		Function[] methods = new Function[qtClass.getQtMetaDataData().getQtMethodsCount()];
		
		Set<Address> possibleQtMethodsAddr = getPossibleQtMethodsAddresses();

		for(int i = qtData.getQtSingalCount(); i < qtData.getQtMethodsCount(); i++)
			try {
				Address slotAddress = solveSlotAddress(i);
				possibleQtMethodsAddr.remove(slotAddress);
				methods[i] = solveQtMethod(slotAddress, i);
			} catch (RuntimeException | MemoryAccessException | InvalidInputException e) {
				log.appendMsg("QtClassSolver: It was not possible to solve the method with index "+i+
						" for the " + qtClass.getName() + " class.");
			}
		
		int signalsLeft = qtData.getQtSingalCount();
		for(Address possibleAdress : possibleQtMethodsAddr)
			try {
				if(signalsLeft == 0)
					break;
				int singalIndex = solveSignalIndex(possibleAdress);
				if(singalIndex == -1)
					continue;
				methods[singalIndex] = solveQtMethod(possibleAdress, singalIndex);
				signalsLeft--;
			} catch (RuntimeException | InvalidInputException | MemoryAccessException e) {
				//logging will be done after
			}
		
		//log the signal methods that coudn't be solved
		for(int i = 0; i < qtData.getQtSingalCount(); i++)
			if(methods[i] == null)
				log.appendMsg("QtClassSolver: It was not possible to solve the method with index "+i+
					" for the " + qtClass.getName() + " class.");

		return methods;
	}
	
	private Set<Address> getPossibleQtMethodsAddresses() {
		Function qtStaticMetacall = qtClass.getQtStaticMetacall();
		InstructionIterator instructions = listing.getInstructions(qtStaticMetacall.getBody(), true);
		Set<Address> possibleQtMethodsAddr = new HashSet<Address>();
		while(instructions.hasNext()) {
			Instruction instruction = instructions.next();
			PcodeOp[] iPcode = instruction.getPcode();
			for(int i = 0; i < iPcode.length; i++) {
				if(!iPcode[i].getMnemonic().equals("CALL") && 
				   !iPcode[i].getMnemonic().equals("COPY") &&
				   !iPcode[i].getMnemonic().equals("BRANCH"))
					continue;
				Address possibleAddress = iPcode[i].getInput(0).getAddress();
				if(!possibleAddress.getAddressSpace().isMemorySpace() &&
				   !possibleAddress.getAddressSpace().isConstantSpace())
					continue;
				if(qtStaticMetacall.getBody().contains(possibleAddress))
					continue;
				if(isExternalObjectAddress(possibleAddress))
					continue;
				possibleQtMethodsAddr.add(possibleAddress);
			}
		}
		return possibleQtMethodsAddr;
	}
	
	private boolean isExternalObjectAddress(Address possibleAddress) {
		Reference[] references = program.getReferenceManager().getReferencesFrom(possibleAddress);
		for(Reference reference : references) {
			if(reference.isExternalReference())
				return true;
		}
		return false;
	}
	
	private Address solveSlotAddress(int index) throws MemoryAccessException {
		Function qtStaticMetacall = qtClass.getQtStaticMetacall();
		AddressSetView metacallBody = qtStaticMetacall.getBody();
		
		PcodeEmulator emulator = new PcodeEmulator(program.getLanguage());
		PcodeThread<byte[]> pCodeThread = emulator.newThread("qt_static_metacall");
		PcodeExecutorState<byte[]> state = emulator.getSharedState();

		byte[] metacallBytes = new byte[(int) (metacallBody.getNumAddresses())+200*8];
		memory.getBytes(metacallBody.getMinAddress(), metacallBytes);
		state.setVar(qtStaticMetacall.getEntryPoint(), metacallBytes.length, true, metacallBytes);
		
		pCodeThread.getExecutor().executeSleigh(String.format("""
				RIP = 0x%s;
				RSP = 0x00001000;
				
				RCX = 0;
				EDX = 0;
				R8D = %d;
				""", qtStaticMetacall.getEntryPoint(), index));
		pCodeThread.overrideContextWithDefault();
		pCodeThread.reInitialize();
		
		while(true) {
			pCodeThread.stepPcodeOp();
			
			PcodeFrame frame = pCodeThread.getFrame();
			if(frame == null)
				continue;
			List<PcodeOp> code = frame.getCode();
			if(frame.index() == code.size() || frame.index() == -1 )
				continue;
			PcodeOp nextPcodeOp = listing.getInstructionAt(pCodeThread.getInstruction().getAddress()).getPcode(true)[frame.index()];
			if(nextPcodeOp.getOpcode() == PcodeOp.CALLIND)
				pCodeThread.skipPcodeOp();
			if(nextPcodeOp.getOpcode() == PcodeOp.RETURN)
				return null;
			if(nextPcodeOp.getOpcode() == PcodeOp.CALL)
				return nextPcodeOp.getInput(0).getAddress();
		}	
	}
	
	private int solveSignalIndex(Address address) throws MemoryAccessException {
		Function qtStaticMetacall = qtClass.getQtStaticMetacall();
		AddressSetView metacallBody = qtStaticMetacall.getBody();
		
		PcodeEmulator emulator = new PcodeEmulator(program.getLanguage());
		PcodeThread<byte[]> pCodeThread = emulator.newThread("qt_static_metacall");
		PcodeExecutorState<byte[]> state = emulator.getSharedState();
		PcodeArithmetic<byte[]> arithmetic = emulator.getArithmetic();

		byte[] metacallBytes = new byte[(int) (metacallBody.getNumAddresses())+200*8];
		memory.getBytes(metacallBody.getMinAddress(), metacallBytes);
		state.setVar(qtStaticMetacall.getEntryPoint(), metacallBytes.length, true, metacallBytes);
		
		AddressSpace addrSpace = qtStaticMetacall.getEntryPoint().getAddressSpace();
		int pSize = addrSpace.getPointerSize();
		
		state.setVar(addrSpace, 0x10000, pSize, true, arithmetic.fromConst(0x8000, pSize));
		state.setVar(addrSpace, 0x8000, 4, true, arithmetic.fromConst(0xffffffff, 4));
		
		state.setVar(addrSpace, 0x10000 + pSize, pSize, true, arithmetic.fromConst(0x5000, pSize));
		state.setVar(addrSpace, 0x5000, pSize, true, arithmetic.fromConst(address.getOffset(), pSize));
		
		pCodeThread.getExecutor().executeSleigh(String.format("""
				RIP = 0x%s;
				RSP = 0x00001000;
				
				RCX = 0;
				EDX = 10;
				R9 = 0x000010000;
				""", qtStaticMetacall.getEntryPoint()));
		pCodeThread.overrideContextWithDefault();
		pCodeThread.reInitialize();
		
		while(true) {
			pCodeThread.stepPcodeOp();
			PcodeFrame frame = pCodeThread.getFrame();
			if(frame == null)
				continue;
			List<PcodeOp> code = frame.getCode();
			if(frame.index() == code.size() || frame.index() == -1 )
				continue;
			PcodeOp nextPcodeOp = listing.getInstructionAt(pCodeThread.getInstruction().getAddress()).getPcode(true)[frame.index()];
			if(nextPcodeOp.getOpcode() == PcodeOp.CALLIND)
				pCodeThread.skipPcodeOp();
			if(nextPcodeOp.getOpcode() == PcodeOp.RETURN) {
				byte[] indexBytes = state.getVar(addrSpace, 0x8000, 4, true, Reason.INSPECT);
				return arithmetic.toBigInteger(indexBytes, Purpose.INSPECT).intValueExact();
			}
		}
	}
	
	private Function solveQtMethod(Address methodAddress, int index) throws InvalidInputException {
		//this is necessary since Ghidra sometimes put functions references in the const space
		AddressSpace ram = program.getAddressFactory().getAddressSpace("ram");
		methodAddress = ram.getAddress(methodAddress.getOffset());
		
		Function method = functionManager.getFunctionAt(methodAddress);
		//should create a function here if method == null but let the user do that since is to much work in code
		
		QtMetaDataMethodInfo methodInfo = qtClass.getQtMetaDataData().getQtMetaDataMethodInfo(index);
		QtMetaStringdataData stringdata = qtClass.getQtMetaStringdataData();
				
		method.setCallingConvention("__thiscall");
		
		DataType returnType = getQtMetaDataType(methodInfo.params().qtReturn());
		method.setReturnType(returnType, SourceType.ANALYSIS);
		
		List<ParameterImpl> params = new ArrayList<ParameterImpl>();
		DataType thisType = new PointerDataType(qtTypesManager.getQtClassType());
		params.add(new ParameterImpl("this", thisType, program, SourceType.ANALYSIS));
		for(int i = 0; i < methodInfo.method().qtArgc(); i++) {
			DataType paramType = getQtMetaDataType(methodInfo.params().qtParameters()[i]);
			String name = stringdata.getQtStringdata(methodInfo.params().qtParametersIndex()[i]);
			name = name.equals("") ? "param_"+i : name;
			params.add(new ParameterImpl(name, paramType, program, SourceType.ANALYSIS));
		}
		
		try {
			method.replaceParameters(params, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
			method.setName(stringdata.getQtStringdata(methodInfo.method().qtName()), SourceType.ANALYSIS);
			method.setParentNamespace(qtClass);
		} catch(DuplicateNameException | CircularDependencyException e) {
			//If we reach here then we assume the name and the namespace were already set
		}
		
		return method;
	}
	
	public DataType[] solveQtProperties() {
		if(qtClass.getQMetaObjectData() == null || qtClass.getQtStaticMetacall() == null)
			return null;
		
		QtMetaDataData qtData = qtClass.getQtMetaDataData();
		DataType[] properties = new DataType[qtData.getQtPropertiesCount()];
		for(int i = 0; i< qtData.getQtPropertiesCount(); i++)	
			try {
				int propertieOffset = solveQtPropertieAddress(i);
				properties[i] = solveQtPropertie(propertieOffset, i);
			} catch (RuntimeException | MemoryAccessException e) {
				log.appendMsg("QtClassSolver: It was not possible to solve the propertie with index "+i+
						" for the " + qtClass.getName() + " class.");
			}
		return properties;
	}
	

	private int solveQtPropertieAddress(int index) throws MemoryAccessException {
		Function qtStaticMetacall = qtClass.getQtStaticMetacall();
		AddressSetView metacallBody = qtStaticMetacall.getBody();
		
		Language language = program.getLanguage();
		Register regRIP = language.getRegister("RIP");
		Register regRSP = language.getRegister("RSP");
		Register regRCX = language.getRegister("RCX");
		Register regRDX = language.getRegister("RDX");
		Register regR8 = language.getRegister("R8");
		Register regR9 = language.getRegister("R9");
		BytesExprPcodeEmulator emulator = new BytesExprPcodeEmulator(language);
		PcodeThread<Pair<byte[], Expr>> pCodeThread = emulator.newThread("qt_static_metacall");
		PcodeExecutorState<Pair<byte[], Expr>> state = emulator.getSharedState();
		PcodeExecutorState<Pair<byte[], Expr>> threadState = pCodeThread.getState();
		PcodeArithmetic<Pair<byte[], Expr>> arithmetic = emulator.getArithmetic();
		
		int size = (int) memory.getBlock(".text").getSize();
		Address address = memory.getBlock(".text").getStart();
		byte[] metacallBytes = new byte[size];
		memory.getBytes(address, metacallBytes);
		state.setVar(address, metacallBytes.length, true, Pair.of(metacallBytes, new VarExpr(address, size)));
		
		AddressSpace addrSpace = qtStaticMetacall.getEntryPoint().getAddressSpace();
		int pSize = addrSpace.getPointerSize();
		
		state.setVar(addrSpace, 0x10000, pSize, true, arithmetic.fromConst(0x8000, pSize));
		state.setVar(addrSpace, 0x8000, 4, true, arithmetic.fromConst(0xffffffff, 4));
		
		threadState.setVar(regRIP, arithmetic.fromConst(qtStaticMetacall.getEntryPoint().getOffset(), pSize));
		threadState.setVar(regRSP, arithmetic.fromConst(0x1000, pSize));
		threadState.setVar(regRCX, arithmetic.fromConst(0, pSize));
		threadState.setVar(regRDX, arithmetic.fromConst(1, pSize));
		threadState.setVar(regR8, arithmetic.fromConst(index, pSize));
		threadState.setVar(regR9, arithmetic.fromConst(0x10000, pSize));
		
		pCodeThread.overrideContextWithDefault();
		pCodeThread.reInitialize();
		
		while(true) {
			pCodeThread.stepPcodeOp();
			PcodeFrame frame = pCodeThread.getFrame();
			if(frame == null)
				continue;
			List<PcodeOp> code = frame.getCode();
			if(frame.index() == code.size() || frame.index() == -1 )
				continue;
			Address instAddr = pCodeThread.getInstruction().getAddress();
			PcodeOp nextPcodeOp = listing.getInstructionAt(instAddr).getPcode(true)[frame.index()];
			if(nextPcodeOp.getOpcode() == PcodeOp.CALLIND)
				pCodeThread.skipPcodeOp();
			if(nextPcodeOp.getOpcode() == PcodeOp.RETURN && metacallBody.contains(instAddr)) {
				Expr expr = state.getVar(addrSpace, 0x8000, pSize, true, Reason.INSPECT).getRight();
				return getQtPropertieOffset(expr);
			}
		}
	}

	private int getQtPropertieOffset(Expr expr) {
		if(expr instanceof LitExpr)
			return ((LitExpr) expr).val().intValue();
		if(expr instanceof AddExpr)
			return getQtPropertieOffset(((AddExpr) expr).l()) + getQtPropertieOffset(((AddExpr) expr).r()); 
		throw new RuntimeException();
	}
	
	private DataType solveQtPropertie(int offset, int index) {
		QtMetaDataPropertie propertieInfo = qtClass.getQtMetaDataData().getQtMetaDataPropertie(index);
		QtMetaStringdataData stringdata = qtClass.getQtMetaStringdataData();
				
		DataType propertieType = getQtMetaDataType(propertieInfo.qtType());
		String propertieName = stringdata.getQtStringdata(propertieInfo.qtName());
		
		Structure qtClassType = qtTypesManager.getQtClassType();
		if(qtClassType.getLength() <= offset)
			qtClassType.insertAtOffset(offset, propertieType, 0, propertieName, null);
		else
			qtClassType.replaceAtOffset(offset, propertieType, 0, propertieName, null);
		
		return propertieType;
	}
	
	private DataType getQtMetaDataType(int type) {
		String typeString = getQtMetaDataTypeString(type);
		if(typeString.endsWith("Star")) {
			typeString = typeString.split("Star")[0]+"*";
		}
		
		int pointerDepth = 0;
		while(typeString.endsWith("*")) {
			pointerDepth++;
			typeString = typeString.substring(0, typeString.length()-1);
		}
		
		DataType dataType = qtTypesManager.findOrCreateQtType(typeString, false);
		if(dataType == null)
			return null;
		
		for(int i = 0; i < pointerDepth; i++) {
			dataType = new PointerDataType(dataType, dataTypeManager);
		}
		
		return dataType;
	}
	
}
