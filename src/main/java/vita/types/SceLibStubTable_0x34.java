package vita.types;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Pointer32DataType;

import vita.misc.TypeManager;
import vita.misc.Utils;

//Firmwares 1.xx?
public class SceLibStubTable_0x34 {
	public static final String STRUCTURE_NAME = SceLibStubTable_0x34.class.getSimpleName();
	public static final int STRUCTURE_SIZE = 0x34;
	
	public short size;
	public short version;
	public short attribute;
	public short num_functions;
	public short num_vars;
	public short num_syms_tls_vars;
	public int reserved1;
	public long library_nid;
	public long library_name_ptr;
	public int reserved2;
	public long func_nid_table;
	public long func_entry_table;
	public long var_nid_table;
	public long var_entry_table;
	public long tls_nid_table;
	public long tls_entry_table;
	
	public final String _LibraryName; //Retrieved library name
	
	public SceLibStubTable_0x34(Address moduleImportsAddr) 
			throws Exception {
		BinaryReader reader = Utils.getMemoryReader(moduleImportsAddr);

		size = reader.readNextShort();
		if (size != STRUCTURE_SIZE) {
			throw new RuntimeException("Invalid size for " + STRUCTURE_NAME + ": " + size + " != " + STRUCTURE_SIZE);
		}
		
		version = reader.readNextShort();
		attribute = reader.readNextShort();
		num_functions = reader.readNextShort();
		num_vars = reader.readNextShort();
		num_syms_tls_vars = reader.readNextShort();
		reserved1 = reader.readNextInt();
		library_nid = reader.readNextUnsignedInt();
		library_name_ptr = reader.readNextUnsignedInt();
		reserved2 = reader.readNextInt();
		func_nid_table = reader.readNextUnsignedInt();
		func_entry_table = reader.readNextUnsignedInt();
		var_nid_table = reader.readNextUnsignedInt();
		var_entry_table = reader.readNextUnsignedInt();
		tls_nid_table = reader.readNextUnsignedInt();
		tls_entry_table = reader.readNextUnsignedInt();
		
		if (library_name_ptr != 0L) {
			Address libNameAddr = Utils.getProgramAddress(library_name_ptr);
			BinaryReader libNameReader = Utils.getMemoryReader(libNameAddr);
			_LibraryName = libNameReader.readNextAsciiString();
			Utils.createAsciiString(libNameAddr);
		} else {
			throw new RuntimeException("SceLibStubTable at address " + moduleImportsAddr.toString() + " doesn't have a library name!");
		}
		
		Utils.createDataInNamespace(moduleImportsAddr, _LibraryName, STRUCTURE_NAME, toDataType());
	}

	private static StructureDataType DATATYPE = null;
	public static DataType toDataType() {
		if (DATATYPE == null) {
			final DataType SceUInt16 = TypeManager.getDataType("SceUInt16");
			final DataType SceUInt32 = TypeManager.getDataType("SceUInt32");
			final DataType NIDPTR = new Pointer32DataType(TypeManager.getDataType("SceUInt32"));
			final DataType ENTRYPTR = new Pointer32DataType(Pointer32DataType.dataType);
			
			DATATYPE = new StructureDataType(TypeManager.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);
			DATATYPE.add(SceUInt16, "size", "Size of this structure");
			DATATYPE.add(Utils.makeArray(TypeManager.getDataType("SceUInt8"), 2), "version", "Library version");
			DATATYPE.add(TypeManager.LIBRARY_ATTRIBUTES, "attributes", "Library attributes");
			DATATYPE.add(SceUInt16, "numFuncs", "Number of functions imported from this library");
			DATATYPE.add(SceUInt16, "numVars", "Number of variables imported from this library");
			DATATYPE.add(SceUInt16, "numTLSVars", "Number of TLS variables imported from this library");
			DATATYPE.add(SceUInt32, "reserved0xC", null);
			DATATYPE.add(SceUInt32, "libraryNID", "Numeric ID of the library");
			DATATYPE.add(new Pointer32DataType(CharDataType.dataType), "pLibName", "Pointer to library name");
			DATATYPE.add(SceUInt32, "reserved0x18", null);
			DATATYPE.add(NIDPTR, "pFuncNidTbl", "Pointer to functions NID table");
			DATATYPE.add(ENTRYPTR, "pFuncEntryTbl", "Pointer to functions entrypoints table");
			
			DATATYPE.add(NIDPTR, "pVarNidTbl", "Pointer to variables NID table");
			DATATYPE.add(ENTRYPTR, "pVarEntryTbl", "Pointer to variables entry table");
			DATATYPE.add(NIDPTR, "pTlsNidTbl", "Pointer to TLS variables NID table");
			DATATYPE.add(ENTRYPTR, "pTlsEntryTbl", "Pointer to TLS variables entry table");
			
			if (DATATYPE.getLength() != STRUCTURE_SIZE)
				System.err.println("Unexpected " + STRUCTURE_NAME + " data type size (" + DATATYPE.getLength() + " != expected " + STRUCTURE_SIZE + " !)");
		}
		
		return DATATYPE;
	}
}
