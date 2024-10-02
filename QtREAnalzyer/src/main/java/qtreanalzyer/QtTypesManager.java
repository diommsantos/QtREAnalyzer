package qtreanalzyer;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;

public class QtTypesManager {
	
		static CategoryPath QT_ROOT = new CategoryPath("/Qt");
		
		static QtTypesManager qtTypesManager = null;
		static String qtClassName;
		static CategoryPath qtClassPath;
		
		Program program;
		DataTypeManager dataTypeManager;
		CParser parser;
		
		Structure qArrayData;
		TypeDef qByteArrayData;
		Structure qMetaObject;
		Structure superData;
		EnumDataType qMetaTypeType;
		
		Map<String, DataType> dataTypes;
	
		public QtTypesManager(Program program) {
			qtTypesManager = this;
			
			this.program = program;
			dataTypeManager = program.getDataTypeManager();
			dataTypeManager.createCategory(new CategoryPath("/Qt"));
			parser = new CParser(dataTypeManager);
			try {
				InputStream qtTypesHeader = QtTypesManager.class.getResourceAsStream("/QtTypes/QtTypes.h");
				parser.parse(qtTypesHeader);
				
				qMetaTypeType = (EnumDataType) parser.getEnums().get("Type");
				qMetaTypeType.setCategoryPath(QT_ROOT);
				dataTypeManager.addDataType(qMetaTypeType, DataTypeConflictHandler.REPLACE_HANDLER);
						
				/**
				 * struct QArrayData {
				 *    int ref; //type should be QtPrivate::RefCount
				 *    int size;
				 *    uint alloc; // should be uint alloc : 31; 
				 *    uint capacityReserved; //should be uint capacityReserved : 1;
				 *
				 *    void *offset; //type should be qptrdiff
				 *};
				 *
				 *typedef QArrayData QByteArrayData;
				 *
				 *struct SuperData;
				 *
				 *struct QMetaObject {
				 *		
				 *	struct { // private data
				 *		SuperData superdata;
				 *        const QByteArrayData *stringdata;
				 *        const uint *data;
				 *        //typedef void (*StaticMetacallFunction)(QObject *, QMetaObject::Call, int, void **);
				 *        void* static_metacall; //type should be StaticMetacallFunction
				 *        const SuperData *relatedMetaObjects;
				 *        void *extradata; //reserved for future use
				 *	} d;
				 *};
				 *
				 *struct SuperData {
				 *	const QMetaObject *direct;
				 *};
				 *
				 */
				
				qArrayData = new StructureDataType(QT_ROOT, "QArrayData", 0, dataTypeManager);
				qArrayData.add(dataTypeManager.getDataType("/int"), "ref", null);
				qArrayData.add(dataTypeManager.getDataType("/int"), "size", null);
				qArrayData.add(dataTypeManager.getDataType("/uint"), "alloc", null);
				qArrayData.add(dataTypeManager.getDataType("/uint"), "capacityReserved", null);
				qArrayData.add(dataTypeManager.getDataType("/void *"), "offset", null);
				qArrayData.setToDefaultPacking();
				qArrayData = (Structure) dataTypeManager.addDataType(qArrayData, DataTypeConflictHandler.REPLACE_HANDLER);
				
				qByteArrayData = new TypedefDataType(QT_ROOT, "QByteArrayData", qArrayData, dataTypeManager);
				qByteArrayData = (TypeDef) dataTypeManager.addDataType(qByteArrayData, DataTypeConflictHandler.REPLACE_HANDLER);
				
				superData = new StructureDataType(QT_ROOT, "SuperData", 0, dataTypeManager);
				superData = (Structure) dataTypeManager.addDataType(superData, DataTypeConflictHandler.REPLACE_HANDLER);
				
				qMetaObject = new StructureDataType(QT_ROOT, "QMetaObject", 0, dataTypeManager);
				StructureDataType structd = new StructureDataType(QT_ROOT, "_struct_d", 0, dataTypeManager);
				qMetaObject.add(structd, "d", null);
				structd.add(superData, "superdata", null);
				structd.add(new PointerDataType(qByteArrayData), "stringdata", null);
				structd.add(dataTypeManager.getDataType("/uint *"), 0, "data", null);
				structd.add(dataTypeManager.getDataType("/void *"), 0, "static_metacall", null);
				structd.add(new PointerDataType(superData), 0, "relatedMetaObjects", null);
				structd.add(dataTypeManager.getDataType("/void *"), 0, "extradata", null);
				structd.setToDefaultPacking();
				qMetaObject.setToDefaultPacking();
				qMetaObject = (Structure) dataTypeManager.addDataType(qMetaObject, DataTypeConflictHandler.REPLACE_HANDLER);
				
				superData.add(new PointerDataType(qMetaObject), "direct", null);
				superData.setToDefaultPacking();
				
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		public static QtTypesManager getQtTypesManager(QtClass qtClass) {
			qtClassName = qtClass.getName();
			qtClassPath = QT_ROOT.extend(qtClass.getName(true).split("::"));
			return qtTypesManager;
		}
		
		public DataType getQArrayData() {
			return qArrayData;
		}
		
		public DataType getQByteArrayData() {
			return qByteArrayData;
		}
		
		public DataType getSuperData() {
			return superData;
		}
		
		public DataType getQMetaObject() {
			return qMetaObject;
		}
		
		public EnumDataType getQMetaTypeTypes() {
			return qMetaTypeType;
		}
		
		public Structure newStruct(String name) {
			Structure struct = new StructureDataType(qtClassPath, name, 0, dataTypeManager);
			return (Structure) dataTypeManager.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
		}
		
		public boolean isQtType(DataType dataType) {
			if(dataType.getCategoryPath().isAncestorOrSelf(QT_ROOT))
				return true;
			return false;
		}
		
		public Structure getQtClassType() {
			Structure qtClassType = (Structure) dataTypeManager.getDataType(qtClassPath, qtClassName);
			return qtClassType != null ? qtClassType : qtTypesManager.newStruct(qtClassName);
		}
		
		public DataType findOrCreateQtType(String dataTypeName, boolean caseSensitive) {
			List<DataType> types = new ArrayList<DataType>();
			dataTypeManager.findDataTypes(dataTypeName, types, caseSensitive, null);
			
			for(DataType dt : types) {
				if(qtTypesManager.isQtType(dt) && dt.getName().equals(dataTypeName)) {
					return dt;
				}	
			}
			
			if(types.size() > 0) {
				for(DataType type : types) {
					if(dataTypeName.toLowerCase(Locale.ROOT).equals(type.getName()))
						return type;
				}
				return types.get(0);
			}
			
			String[] dataTypePath = dataTypeName.split("::");
			Structure dataType = new StructureDataType(dataTypePath[dataTypePath.length-1], 0, dataTypeManager);
			try {
				if(dataTypePath.length > 1)
					dataType.setCategoryPath(new CategoryPath(QT_ROOT, Arrays.copyOfRange(dataTypePath, 0, dataTypePath.length-1)));
				else
					dataType.setCategoryPath(QT_ROOT);
				return dataTypeManager.addDataType(dataType, DataTypeConflictHandler.REPLACE_HANDLER);
			} catch (DuplicateNameException e) {
				return null;
			}
			
		}
	
}
