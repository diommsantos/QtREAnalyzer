package qtreanalzyer;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.importer.MessageLog;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.pcode.exec.SleighProgramCompiler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
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
		this.qtTypesManager = QtTypesManager.getQtTypesManager();
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
		
		StructureDataType qtMetaStringdata = new StructureDataType("qt_meta_stringdata_"+qtClass.getName()+"_t", 0, dataTypeManager);
		
		ArrayDataType data = new ArrayDataType(qByteArrayData, numDataEntries);
		
		DataType charType = dataTypeManager.getDataType("/char");
		StructureDataType stringdata = new StructureDataType("stringdata", 0);
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
		StructureDataType qtMetaDataType = new StructureDataType("qt_meta_data_"+qtClass.getName(), 0, dataTypeManager);
		qtMetaDataType.add(intDataType, "revision", null);
		qtMetaDataType.add(intDataType, "classname", null);
		qtMetaDataType.add(intDataType, "classinfo_count", null);qtMetaDataType.add(intDataType, "classinfo_index", null);
		qtMetaDataType.add(intDataType, "methods_count", null);qtMetaDataType.add(intDataType, "mehtods_index", null);
		qtMetaDataType.add(intDataType, "properties_count", null);qtMetaDataType.add(intDataType, "properties_index", null);
		qtMetaDataType.add(intDataType, "enum_sets_count", null);qtMetaDataType.add(intDataType, "enums_sets_index", null);
		//qtMetaDataType.add(intDataType, "constructors_count", null);qtMetaDataType.add(intDataType, "constructors_index", null);
		//qtMetaDataType.add(intDataType, "flags", null);
		//qtMetaDataType.add(intDataType, "signalCount", null);
		
		int methodsCount = memory.getInt(qtMetaDataAddress.add(intLenght * 4));
		int methodsIndex = memory.getInt(qtMetaDataAddress.add(intLenght * 5));
		int propertiesCount = memory.getInt(qtMetaDataAddress.add(intLenght * 6));
		int propertiesIndex = memory.getInt(qtMetaDataAddress.add(intLenght * 7));
		
		StructureDataType qtMetaDataMethodDT = new StructureDataType("qt_meta_data_method", 0);
		qtMetaDataMethodDT.add(intDataType, "name", null);
		qtMetaDataMethodDT.add(intDataType, "argc", null);
		qtMetaDataMethodDT.add(intDataType, "parameters", null);
		qtMetaDataMethodDT.add(intDataType, "tag", null);
		qtMetaDataMethodDT.add(intDataType, "flags", null);
		
		if(methodsCount > 0)
			qtMetaDataType.insertAtOffset(intLenght*methodsIndex, 
				new ArrayDataType(qtMetaDataMethodDT, methodsCount), 0);
		
		//constructs the method parameters
		StructureDataType qtMetaDataParamsDT = new StructureDataType("qt_meta_data_parameters", 0);
		int parameters0 = memory.getInt(qtMetaDataAddress.add(intLenght*(methodsIndex+2)));
		for(int i = 0; i < methodsCount; i++) {
			int argc = memory.getInt(qtMetaDataAddress.add(intLenght*(methodsIndex+1+i*5)));
			int parameters = memory.getInt(qtMetaDataAddress.add(intLenght*(methodsIndex+2+i*5)));
			int relativeIndex = parameters-parameters0;
			
			//construct qt_meta_data_parameters DataType
			StructureDataType qtMetaDataParamDT = new StructureDataType("qt_meta_data_parameters"+i, 0);
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
		
		StructureDataType qtMetaDataPropsDT = new StructureDataType("qt_meta_data_properties",0);
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
			
			qtStaticMetacall.setName("qt_static_metacall", SourceType.ANALYSIS);
			qtStaticMetacall.setParentNamespace(qtClass);
			
			qtStaticMetacall.setCallingConvention("__fastcall");
			
			DataType voidType = dataTypeManager.getDataType("/void");
			qtStaticMetacall.setReturnType(voidType, SourceType.ANALYSIS);
			
			DataType qMetaObjectPtr = new PointerDataType(qtTypesManager.getQMetaObject(), dataTypeManager);
			ParameterImpl _o = new ParameterImpl("_o", qMetaObjectPtr, program, SourceType.ANALYSIS);
			
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
		signature += getQtMetaDataType(returnType) + " ";
		
		int methodName = methodInfo.method().qtName();
		signature += stringdata.getQtStringdata(methodName);
		
		signature += "(";
		int numParams = methodInfo.method().qtArgc();
		for(int i = 0; i < numParams; i++) {
			int paramType = methodInfo.params().qtParameters()[i];
			signature += getQtMetaDataType(paramType) + " ";
			
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
		signature += getQtMetaDataType(propertieType) + " ";
		
		int propertieName = propertie.qtName();
		signature += stringdata.getQtStringdata(propertieName);
		
		return signature;
	}
	
	private String getQtMetaDataType(int type) {
		if(qMetaTypeTypes.contains(type))
			return qMetaTypeTypes.getName(type);
		if((type & 0x80000000) == 0x80000000)
			return qtClass.getQtMetaStringdataData().getQtStringdata(type - 0x80000000);
		return "unknown";
	}
	
	public Address getMethod(int index, Data qMetaObject) {
		PcodeEmulator emulator = new PcodeEmulator(program.getLanguage());
		PcodeThread<byte[]> pCodeThread = emulator.newThread("qt_static_metacall");
		//pCodeThread.overrideCounter(qMetaObject.getComponent(0).getComponent(3).
			//	getOperandReferences(0)[0].getToAddress().add(4));
		Function qtStaticMetaCall = program.getFunctionManager().getFunctionAt(qMetaObject.getComponent(0).getComponent(3).
				getOperandReferences(0)[0].getToAddress());
		byte[] qtStaticMetaCallB = new byte[1000];
		try {
			program.getMemory().getBlock(qtStaticMetaCall.getBody().getMinAddress())
			.getBytes(qtStaticMetaCall.getBody().getMinAddress(), qtStaticMetaCallB, 0, (int) qtStaticMetaCall.getBody().getNumAddresses());
		} catch (IndexOutOfBoundsException | MemoryAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		emulator.getSharedState()
		.setVar(program.getAddressFactory().getDefaultAddressSpace().getAddress(0x200), 1000, true, qtStaticMetaCallB);
		PcodeUseropLibrary<byte[]> library = pCodeThread.getUseropLibrary();
		PcodeProgram init =
				SleighProgramCompiler.compileProgram((SleighLanguage) program.getLanguage(), "init", String.format("""
						RIP = 0x%s;
						RSP = 0x00001000;
						""", program.getAddressFactory().getDefaultAddressSpace().getAddress(0x200)), library);
		pCodeThread.getExecutor().execute(init, library);
		pCodeThread.overrideContextWithDefault();
		pCodeThread.reInitialize();
		PcodeOp[] pCodeOps;
		outerLoop:
		while(true) {
			pCodeThread.stepInstruction();
			pCodeThread.stepPcodeOp();
			pCodeOps = pCodeThread.getInstruction().getPcode();
			pCodeThread.finishInstruction();
			for(int i = 0; i < pCodeOps.length; i++) {
				if(pCodeOps[i].getMnemonic().equals("CALL")) {
					break outerLoop;
				}
				if(pCodeOps[i].getMnemonic().equals("CALLIND")) {
					return null;
				}
				if(pCodeOps[i].getMnemonic().equals("RET")) {
					return null;
				}
			}
		}
		return pCodeThread.getInstruction().getAddress();
	}
}
