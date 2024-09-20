package qtreanalzyer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.pcodeCPort.sleighbase.address_set;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;

public class QtTypesManager {
		
		static QtTypesManager qtTypesManager = null;
		
		Program program;
		DataTypeManager dataTypeManager;
		CParser parser;
		
		Map<String,DataType> composites;
		Map<String,DataType> enums;
	
		public QtTypesManager(Program program) {
			qtTypesManager = this;
			
			this.program = program;
			dataTypeManager = program.getDataTypeManager();
			parser = new CParser(dataTypeManager);
			try {
				InputStream qtTypesHeader = Files.newInputStream(Paths.get("src\\main\\java\\QtTypes\\QtTypes.h"));
				parser.parse(qtTypesHeader);
				composites = parser.getComposites();
				enums = parser.getEnums();
			} catch (IOException | ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		public static QtTypesManager getQtTypesManager() {
			return qtTypesManager;
		}
		
		public DataType getQArrayData() {
			return composites.get("QArrayData");
		}
		
		public DataType getQByteArrayData() {
			return composites.get("QArrayData");
		}
		
		public DataType getSuperData() {
			return composites.get("SuperData");
		}
		
		public DataType getQMetaObject() {
			return composites.get("QMetaObject");
		}
		
		public EnumDataType getQMetaTypeTypes() {
			return (EnumDataType) enums.get("Type");
		}
	
}
