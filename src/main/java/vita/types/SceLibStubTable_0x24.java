package vita.types;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.StringDataType;

import vita.misc.TypeManager;
import vita.misc.Utils;

//Firmware 3.xx?
public class SceLibStubTable_0x24 {
	public static final String STRUCTURE_NAME = SceLibStubTable_0x24.class.getSimpleName();
	public static final int STRUCTURE_SIZE = 0x24;
	
	public short size;
	public short version;
	public short attribute;
	public short num_functions;
	public short num_vars;
	public short num_tls_variables;
	public long library_nid;
	public long library_name_ptr;
	public long func_nid_table;
	public long func_entry_table;
	public long var_nid_table;
	public long var_entry_table;
	private Address _selfAddress;

	
	public String _LibraryName;	//Parsed library name - not part of the struct itself

	public SceLibStubTable_0x24(Address moduleImportsAddr) throws Exception {
		_selfAddress = moduleImportsAddr;
		
		BinaryReader reader = Utils.getMemoryReader(moduleImportsAddr);
		size = reader.readNextShort();
		version = reader.readNextShort();
		attribute = reader.readNextShort();
		num_functions = reader.readNextShort();
		num_vars = reader.readNextShort();
		num_tls_variables = reader.readNextShort();
		library_nid = reader.readNextUnsignedInt();
		library_name_ptr = reader.readNextUnsignedInt();
		func_nid_table = reader.readNextUnsignedInt();
		func_entry_table = reader.readNextUnsignedInt();
		var_nid_table = reader.readNextUnsignedInt();
		var_entry_table = reader.readNextUnsignedInt();
		
		if (library_name_ptr != 0L) {
			BinaryReader libNameReader = Utils.getMemoryReader(Utils.getProgramAddress(library_name_ptr));
			_LibraryName = libNameReader.readNextAsciiString();
		} else {
			throw new RuntimeException("SceLibStubTable at address " + moduleImportsAddr.toString() + " doesn't have a library name!");
		}
		
		Utils.createDataInNamespace(_selfAddress, _LibraryName, STRUCTURE_NAME, toDataType());
	}

	private static StructureDataType DATATYPE = null;
	public static DataType toDataType() {
		if (DATATYPE == null) {
			final DataType SceUInt16 = TypeManager.getDataType("SceUInt16");
			
			DATATYPE = new StructureDataType(TypeManager.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);
			DATATYPE.add(SceUInt16, "size", "Size of this structure");
			DATATYPE.add(SceUInt16, "version", null);
			DATATYPE.add(SceUInt16, "attribute", null);
			DATATYPE.add(SceUInt16, "num_functions", "Number of functions imported from this library");
			DATATYPE.add(SceUInt16, "num_vars", "Number of variables imported from this library");
			DATATYPE.add(SceUInt16, "num_tls", "Number of TLS variables imported from this library");
			DATATYPE.add(TypeManager.getDataType("SceUInt32"), "libraryNID", "Numeric ID of library");
			DATATYPE.add(new Pointer32DataType(StringDataType.dataType), "library_name", "Pointer to library name");
			DATATYPE.add(Pointer32DataType.dataType, "func_nid_table", "Pointer to functions NID table");
			DATATYPE.add(Pointer32DataType.dataType, "func_entry_table", "Pointer to functions entrypoints table");
			DATATYPE.add(Pointer32DataType.dataType, "var_nid_table", "Pointer to variables NID table");
			DATATYPE.add(Pointer32DataType.dataType, "var_entry_table", "Pointer to variables entry table");
			
			if (DATATYPE.getLength() != STRUCTURE_SIZE)
				System.err.println("Unexpected " + STRUCTURE_NAME + " data type size (" + DATATYPE.getLength() + " != expected " + STRUCTURE_SIZE + " !)");
		}
		
		return DATATYPE;
	}

}
