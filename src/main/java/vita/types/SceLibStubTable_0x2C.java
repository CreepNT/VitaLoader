package vita.types;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.Pointer32DataType;

import vita.misc.TypeManager;
import vita.misc.Utils;

//Used on firmware 0.931-?
public class SceLibStubTable_0x2C {
	public static final String STRUCTURE_NAME = SceLibStubTable_0x2C.class.getSimpleName();
	public static final int STRUCTURE_SIZE = 0x2C;
	
	public short size;
	public short[] version = { 0, 0 };
	public short attributes;
	public short numFunctions;
	public short numVars;
	public short numTlsVars;
	
	
	public long reserved0xC;
	public long pLibName;
	public long pFuncNidTbl;
	public long pFuncEntryTbl;
	public long pVarNidTbl;
	public long pVarEntryTbl;
	public long pTlsNidTbl;
	public long pTlsEntryTbl;
	
	public long library_nid;
	
	public final String _LibraryName; //Retrieved library name
	public final long _sce_package_version;
	
	public SceLibStubTable_0x2C(Address moduleImportsAddr) 
			throws Exception {
		BinaryReader reader = Utils.getMemoryReader(moduleImportsAddr);

		size = reader.readNextShort();
		if (size != STRUCTURE_SIZE) {
			throw new RuntimeException("Invalid size for " + STRUCTURE_NAME + ": " + size + " != " + STRUCTURE_SIZE);
		}
		
		version[0] = reader.readNextByte();
		version[1] = reader.readNextByte();
		attributes = reader.readNextShort();
		numFunctions = reader.readNextShort();
		numVars = reader.readNextShort();
		numTlsVars = reader.readNextShort();
		
		reserved0xC = reader.readNextUnsignedInt();
		pLibName = reader.readNextUnsignedInt();
		pFuncNidTbl = reader.readNextUnsignedInt();
		pFuncEntryTbl = reader.readNextUnsignedInt();
		pVarNidTbl = reader.readNextUnsignedInt();
		pVarEntryTbl = reader.readNextUnsignedInt();
		pTlsNidTbl = reader.readNextUnsignedInt();
		pTlsEntryTbl = reader.readNextUnsignedInt();
		
		if (pLibName == 0L) {
			throw new RuntimeException("SceLibStubTable at address " + moduleImportsAddr.toString() + " doesn't have a library name!");
		}
		
		Address libNidAddr = Utils.getProgramAddressUnchecked(pLibName - 8);
		if (libNidAddr == null) { //should never happen
			throw new RuntimeException(String.format("SceLibStubTable at address " + moduleImportsAddr.toString() + " has unexpected name pointer 0x%08X!", pLibName - 8));
		}
		
		BinaryReader libraryMetadataReader = Utils.getMemoryReader(libNidAddr);
		library_nid = libraryMetadataReader.readNextUnsignedInt();
		_sce_package_version = libraryMetadataReader.readNextUnsignedInt();
		_LibraryName = libraryMetadataReader.readNextAsciiString();
		
		//Sony changed the meaning of pLibName between 0.902 and 0.931 because why the fuck not
		//This should be a good enough heuristic, at worse this can be removed entirely.
		if (_sce_package_version == 0L) {
			Utils.createDataInNamespace(libNidAddr, _LibraryName, "_" + _LibraryName + "_nid", TypeManager.u32);
			Utils.createDataInNamespace(libNidAddr.add(4), _LibraryName, "_sce_package_version_" + _LibraryName, TypeManager.u32);
		} else {
			//On 0.931 there's no library NID, what we read is garbage
			//Fallback to "no NID" case
			library_nid = -1L;
		}
		
		Utils.createDataInNamespace(libNidAddr.add(8), _LibraryName, "_" + _LibraryName + "_stub_str", new TerminatedStringDataType());
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
			DATATYPE.add(new Pointer32DataType(CharDataType.dataType), "pLibName", "Pointer to library name");
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
