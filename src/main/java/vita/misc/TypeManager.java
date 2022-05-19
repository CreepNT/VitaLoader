package vita.misc;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.ImageBaseOffset32DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.SignedByteDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.WideChar16DataType;
import ghidra.program.model.data.WideChar32DataType;

//Type manager is responsible for adding in the SCE datatypes
public final class TypeManager {
	//Category used to store loader provided datatypes
	public final static CategoryPath LOADER_CATPATH = new CategoryPath("/VitaLoader");
		
	//Category all the base SCE data types will be stored under
	public final static CategoryPath SCE_TYPES_CATPATH = new CategoryPath("/SCE");
		
	//Category all types from the database will be stored under
	public final static CategoryPath TYPES_DB_CATPATH = new CategoryPath("/DBTypes");

	
	//For convenience
	public final static DataType IBO32 = new ImageBaseOffset32DataType();
	public final static DataType PVOID = new Pointer32DataType(VoidDataType.dataType);
	public final static DataType u64 = UnsignedLongLongDataType.dataType;
	public final static DataType s64 = LongLongDataType.dataType;
	public final static DataType u32 = UnsignedIntegerDataType.dataType;
	public final static DataType s32 = IntegerDataType.dataType;
	public final static DataType u16 = UnsignedShortDataType.dataType;
	public final static DataType s16 = ShortDataType.dataType;
	public final static DataType u8 = ByteDataType.dataType;
	public final static DataType s8 = SignedByteDataType.dataType;
	public final static DataType f32 = FloatDataType.dataType;
	public final static DataType f64 = DoubleDataType.dataType;
	
	public static EnumDataType LIBRARY_ATTRIBUTES = null;
	
	//public final static DataType size_t = new TypedefDataType(new CategoryPath("/stddef.h"), "size_t", u32);

	
	private static Map<String, DataType> DATATYPES = new HashMap<>();

	public static void addDataType(DataType dt) {
		DATATYPES.put(dt.getName(), dt);
	}
	
	public static void addDataType(String name, DataType dt) {
		DATATYPES.put(name, dt);
	}
	
	public static DataType getDataType(String name) {
		return DATATYPES.get(name);
	}
	
	private static DataType _addSCETypedef(String name, DataType typedef) {
		DataType dt = new TypedefDataType(SCE_TYPES_CATPATH, name, typedef);
		Utils.registerDataType(dt);
		DATATYPES.put(name, dt);
		return dt;
	}
	
	public static void initialize() {
		//Create and add all SCE types to hashmap
		_addSCETypedef("SceChar8",  	CharDataType.dataType);
		_addSCETypedef("SceUChar8", 	UnsignedCharDataType.dataType);
		_addSCETypedef("SceInt8", 		s8);
		_addSCETypedef("SceUInt8", 		u8);
		_addSCETypedef("SceShort16", 	s16);
		_addSCETypedef("SceUShort16", 	u16);
		_addSCETypedef("SceInt16", 		s16);
		_addSCETypedef("SceUInt16", 	u16);
		_addSCETypedef("SceInt32",		s32);
		_addSCETypedef("SceUInt32",     u32);
		_addSCETypedef("SceInt",        s32);
		_addSCETypedef("SceUInt",       u32);
		_addSCETypedef("SceLong",       s32);
		_addSCETypedef("SceULong",      u32);
		_addSCETypedef("SceInt64",      s64);
		DataType SceInt64 = _addSCETypedef("SceUInt64", u64);
		_addSCETypedef("SceLong64",     s64);
		_addSCETypedef("SceULong64",    u64);
		_addSCETypedef("SceFloat",      f32);
		_addSCETypedef("SceFloat32",    f32);
		_addSCETypedef("SceDouble",     f64);
		_addSCETypedef("SceDouble64",   f64);
		_addSCETypedef("SceSByte",      s8);
		_addSCETypedef("SceSByte8",     s8);
		_addSCETypedef("SceByte",       u8);
		_addSCETypedef("SceByte8",      u8);
		_addSCETypedef("SceWChar16",    WideChar16DataType.dataType);
		_addSCETypedef("SceWChar32",    WideChar32DataType.dataType);
		_addSCETypedef("SceBool",       s32);
		_addSCETypedef("SceIntPtr",     s32);
		_addSCETypedef("SceUIntPtr",    u32);
		_addSCETypedef("SceVoid",       VoidDataType.dataType);
		_addSCETypedef("ScePVoid",      new Pointer32DataType(VoidDataType.dataType));
		
		//TODO: add structs
		
		DataType SceSize = _addSCETypedef("SceSize", u32);
		_addSCETypedef("ScePSize",     SceSize);
		_addSCETypedef("SceVSize",     SceSize);
		DataType SceSSize = _addSCETypedef("SceSSize", s32);
		_addSCETypedef("ScePSSize",    SceSSize);
		_addSCETypedef("SceVSSize",    SceSSize);
		_addSCETypedef("SceUIntVAddr", u32);
		_addSCETypedef("SceUIntPAddr", u32); //not sure if official name
		
		DataType SceUID = _addSCETypedef("SceUID", s32);
		_addSCETypedef("SceName",      new Pointer32DataType(CharDataType.dataType));
		_addSCETypedef("SceOff",       SceInt64);
		_addSCETypedef("ScePID",       SceUID);
		
		//Add common constants
		EnumDataType SCE_CONSTANTS = new EnumDataType(SCE_TYPES_CATPATH, "SCE_CONSTANTS", 4);
		SCE_CONSTANTS.add("SCE_NULL", 0);
		SCE_CONSTANTS.add("SCE_OK", 0);
		SCE_CONSTANTS.add("SCE_FALSE", 0);
		SCE_CONSTANTS.add("SCE_TRUE", 1);
		SCE_CONSTANTS.add("SCE_UID_INVALID_UID", 0xFFFFFFFFL);
		addDataType(SCE_CONSTANTS);
		
		//Add library attributes - this *could* be done in imports/exports but it's better if centralized
		//SCE_LIBRARY_ATTR prefix isn't official(?)
		LIBRARY_ATTRIBUTES  = new EnumDataType(SCE_TYPES_CATPATH, "LIBRARY_ATTRIBUTES", 2);
		LIBRARY_ATTRIBUTES.add("SCE_LIBRARY_ATTR_MAIN_EXPORT", 0x8000, "Module main export (NONAME library)");
		LIBRARY_ATTRIBUTES.add("SCE_LIBRARY_ATTR_USER_IMPORTABLE", 0x4000, "Functions of this library are user-importable (syscall export)");
		LIBRARY_ATTRIBUTES.add("SCE_LIBRARY_ATTR_WEAK_IMPORT", 0x8, "Weak import library - module can boot even if library isn't found");
		LIBRARY_ATTRIBUTES.add("SCE_LIBRARY_ATTR_NOLINK_EXPORT", 0x4);
		LIBRARY_ATTRIBUTES.add("SCE_LIBRARY_ATTR_WEAK_EXPORT", 0x2);
		LIBRARY_ATTRIBUTES.add("SCE_LIBRARY_ATTR_AUTO_EXPORT", 0x1, "Library is exported, and other modules can import from it");
		LIBRARY_ATTRIBUTES.add("SCE_LIBRARY_ATTR_NONE", 0x0);
		addDataType(LIBRARY_ATTRIBUTES);
	}
	
	DataType getDataTypeFromName(String name) {
		return DATATYPES.get(name);
	}
}
