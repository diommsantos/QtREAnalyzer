package qtreanalzyer;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;

/**
 * Represents a C++ class that inherits the QObject Qt class.
 * Users of this class should check if it inherits QObject with {@link #isQtClass()}
 * before invoking other methods.
 */
public class QtClass extends RttiClass{
	
	boolean qtClass = false;
	
	QMetaObjectData qMetaObjectData;
	QtMetaStringdataData qtMetaStringdataData;
	QtMetaDataData qtMetaDataData;
	
	QtClassSolver qtClassSolver;
	
	QtClass(GhidraClass ghidraClass) {
		super(ghidraClass);
		if(hasRtti()) {
			qtClass = checkQtClass();
		}
		qtClassSolver = new QtClassSolver(this);
	}
	
	/**
	 * Checks whether this class inherits QObject
	 * @return true if this class inherits QObject
	 */
	private boolean checkQtClass() {
		return inherits("QObject");
	}
	
	/**
	 * 
	 * @return true if this class inherits QObject
	 */
	public boolean isQtClass() {
		return qtClass;
	}
	
	public void solve() {
		Data qMetaObject = qtClassSolver.solveQMetaObject();
		qMetaObjectData = qMetaObject != null ? new QMetaObjectData(qMetaObject) : null;
		
		Data qtMetaStringdata = qtClassSolver.solveQtMetaStringdata();
		qtMetaStringdataData = qtMetaStringdata != null ? new QtMetaStringdataData(qtMetaStringdata) : null;
		
		Data qtMetaData = qtClassSolver.solveQtMetaData();
		qtMetaDataData = qtMetaData != null ? new QtMetaDataData(qtMetaData) : null;
	}
	
	public QMetaObjectData getQMetaObjectData() {
		return qMetaObjectData;
	}

}

/**
 * Represents an abstract C++ Qt struct object.
 */
abstract class QtData{
	
	Data data;
	
	public QtData(Data data) {
		this.data = data;
	}
	
	Data getData() {
		return data;
	}
}

class QArrayDataData extends QtData{
	
	int qtRef;
	int qtSize;
	long qtAlloc; //represents an unsigned integer
	long qtCapacityReserved; //represents an unsigned integer
	long qtOffset; //represents an address offset
	
	public QArrayDataData(Data data) {
		super(data);
		try {
			this.qtRef = data.getComponent(0).getInt(0);
			this.qtSize = data.getComponent(1).getInt(0);
			this.qtAlloc = Integer.toUnsignedLong(data.getComponent(2).getInt(0));
			this.qtCapacityReserved = Integer.toUnsignedLong(data.getComponent(3).getInt(0));
			this.qtOffset = data.getComponent(3).getLong(0);
		} catch (MemoryAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public int getRef() {
		return qtRef;
	}
	
	public int getSize() {
		return qtSize;
	}
	
	public long getAlloc() {
		return qtAlloc;
	}
	
	public long getCapacityReserved() {
		return qtCapacityReserved;
	}
	
	public long getOffset() {
		return qtOffset;
	}
}

/**
 * Represents a C++ object of type QMetaObject. 
 */
class QMetaObjectData extends QtData{
	
	Address qtSuperdata;
	Address qtStringdata;
	Address qtData;
	Address qtStatic_metacall;
	Address qtRelatedMetaObjects;
	Address qtExtradata;
	
	public QMetaObjectData(Data data) {
		super(data);
		Data dData = data.getComponent(0);
		try {
			this.qtSuperdata          = (Address) dData.getComponent(0).getComponent(0).getValue();
			this.qtStringdata         = (Address) dData.getComponent(1).getValue();
			this.qtData               = (Address) dData.getComponent(2).getValue();
			this.qtStatic_metacall    = (Address) dData.getComponent(3).getValue();
			this.qtRelatedMetaObjects = (Address) dData.getComponent(4).getValue();
			this.qtExtradata          = (Address) dData.getComponent(5).getValue();
		} catch (AddressOutOfBoundsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public Address getQtSuperdata() {
		return qtSuperdata;
	}
	
	public Address getStringdata() {
		return qtStringdata;
	}
	
	public Address getQtData() {
		return qtData;
	}
	
	public Address getQtStatic_metacall() {
		return qtStatic_metacall;
	}
	 
	public Address getQtRelatedMetaObjects() {
		return qtRelatedMetaObjects;
	}
	
	public Address getQtExtraData() {
		return qtExtradata;
	}
}

/**
 * Represents a C++ object of type qt_meta_stringdata_{classname}_t 
 * where {classname} is the name of the Qt class this object is associated to. 
 */
class QtMetaStringdataData extends QtData {
	
	int numEntries; // represents how many strings are in this qt_meta_stringdata_{classname}_t struct
	QArrayDataData[] qtData;
	String[] qtStringdata;
	
	public QtMetaStringdataData(Data data) {
		super(data);
		this.numEntries = ((Array) data.getComponent(0).getDataType()).getNumElements();
		qtData = new QArrayDataData[numEntries];
		qtStringdata = new String[numEntries];
		for(int i = 0; i < numEntries; i++) {
			qtData[i] = new QArrayDataData(data.getComponent(0).getComponent(i));
			qtStringdata[i] = (String) data.getComponent(1).getComponent(i).getValue();
		}
	}
	
	public QArrayDataData getQtData(int index) {
		return qtData[index];
	}
	
	public String getQtStringdata(int index) {
		return qtStringdata[index];
	}
	
}

/**
 * Represents a C++ object of type qt_meta_data_{classname} 
 * where {classname} is the name of the Qt class this object is associated to. 
 */
class QtMetaDataData extends QtData {

	int qtRevision,
		qtClassname,
		qtClassinfo_count,  qtClassinfo_index,
		qtMethods_count,    qtMethods_index,
		qtProperties_count, qtProperties_index,
		qtEnum_sets_count,  qtEnum_sets_index;
	
	record QtMetaDataMethod(
		int qtName,
		int qtArgc,
		int qtParameter,
		int qtTag,
		int qtFlags
	) {}
	
	record QtMetaDataParameters(
		int qtReturn,
		int[] qtParameters,
		int[] qtParametersIndex
	) {}
	
	QtMetaDataMethod[] qtMetaDataMethods;
	QtMetaDataParameters[] qtMetaDataParameters;
	
	record QtMetaDataPropertie(
		int qtName,
		int qtType,
		int qtFlags
	) {}
	
	QtMetaDataPropertie[] qtMetaDataProperties;
	
	public QtMetaDataData(Data data) {
		super(data);
		
		qtRevision         = (int) ((Scalar) data.getComponent(0).getValue()).getValue();
		qtClassname        = (int) ((Scalar) data.getComponent(1).getValue()).getValue();
		
		qtClassinfo_count  = (int) ((Scalar) data.getComponent(2).getValue()).getValue(); 
		qtClassinfo_index  = (int) ((Scalar) data.getComponent(3).getValue()).getValue();
		
		qtMethods_count    = (int) ((Scalar) data.getComponent(4).getValue()).getValue();    
		qtMethods_index    = (int) ((Scalar) data.getComponent(5).getValue()).getValue();
		
		qtProperties_count = (int) ((Scalar) data.getComponent(6).getValue()).getValue(); 
		qtProperties_index = (int) ((Scalar) data.getComponent(7).getValue()).getValue();
		
		qtEnum_sets_count  = (int) ((Scalar) data.getComponent(8).getValue()).getValue();  
		qtEnum_sets_index  = (int) ((Scalar) data.getComponent(9).getValue()).getValue();
		
		qtMetaDataMethods = new QtMetaDataMethod[qtMethods_count];
		qtMetaDataParameters = new QtMetaDataParameters[qtMethods_count];
		
		qtMetaDataProperties = new QtMetaDataPropertie[qtProperties_count];
		
		int intLenght = data.getComponent(0).getBaseDataType().getLength();
		
		for(int i = 0; i < qtMethods_count; i++) {
			Data qtMetaDataMethodData = data.getComponentContaining(qtMethods_index * intLenght).getComponent(i);
			qtMetaDataMethods[i] = new QtMetaDataMethod(
											(int) ((Scalar) qtMetaDataMethodData.getComponent(0).getValue()).getValue(), 
											(int) ((Scalar) qtMetaDataMethodData.getComponent(1).getValue()).getValue(), 
											(int) ((Scalar) qtMetaDataMethodData.getComponent(2).getValue()).getValue(), 
											(int) ((Scalar) qtMetaDataMethodData.getComponent(3).getValue()).getValue(), 
											(int) ((Scalar) qtMetaDataMethodData.getComponent(4).getValue()).getValue()
									   );
			
			int qtArgc = qtMetaDataMethods[i].qtArgc();
			Data qtMetaDataParametersData = data.getComponentContaining((qtMethods_index+1) * intLenght).getComponent(i);
			int[] qtParameters = 	  new int[qtArgc];
			int[] qtParametersIndex = new int[qtArgc];
			for(int j = 0; j < qtArgc; j++) {
				qtParameters[j] = (int) ((Scalar) qtMetaDataParametersData.getComponent(j + 1).getValue()).getValue();
				qtParametersIndex[j] = (int) ((Scalar) qtMetaDataParametersData.getComponent(j + 1 + qtArgc).getValue()).getValue();
			}
			qtMetaDataParameters[i] = new QtMetaDataParameters(
											(int) ((Scalar) qtMetaDataParametersData.getComponent(0).getValue()).getValue(), 
											qtParameters, 
											qtParametersIndex
										  );
		}
		
		for(int i = 0; i < qtProperties_count; i++) {
			Data qtMetaDataPropertieData = data.getComponent(qtProperties_index * intLenght).getComponent(i);
			qtMetaDataProperties[i] = new QtMetaDataPropertie(
										  	(int) ((Scalar) qtMetaDataPropertieData.getComponent(0).getValue()).getValue(),
										  	(int) ((Scalar) qtMetaDataPropertieData.getComponent(1).getValue()).getValue(),
										  	(int) ((Scalar) qtMetaDataPropertieData.getComponent(2).getValue()).getValue()
										  );
		}
	}
	
}
