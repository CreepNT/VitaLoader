package vita.misc;


import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.Integer16DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.SignedCharDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedInteger16DataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import vita.elf.VitaElfExtension.ProcessingContext;
import ghidra.program.model.data.PointerDataType;

public class TypesManager {
	//Category all structures created through the TypesManager will be stored under
	private final static CategoryPath LOADER_CATPATH = new CategoryPath("/VitaLoader");
	
	//Category all the base SCE data types will be stored under
	public final static CategoryPath SCE_TYPES_CATPATH = new CategoryPath("/SCE");
	
	//Used for bytes manipulation functions
	private final static boolean IS_LITTLE_ENDIAN = true;
	
	public final static DataType PVOID = new Pointer32DataType(StructConverter.VOID);
	public final static DataType u64 = UnsignedLongLongDataType.dataType;
	public final static DataType s64 = LongLongDataType.dataType;
	public final static DataType u32 = UnsignedIntegerDataType.dataType;
	public final static DataType s32 = IntegerDataType.dataType;
	public final static DataType u16 = UnsignedInteger16DataType.dataType;
	public final static DataType s16 = Integer16DataType.dataType;
	public final static DataType u8 = UnsignedCharDataType.dataType;
	public final static DataType s8 = SignedCharDataType.dataType;
	public final static DataType f32 = FloatDataType.dataType;
	public final static DataType f64 = DoubleDataType.dataType;
	public final static DataType size_t = new TypedefDataType(new CategoryPath("/stddef.h"), "size_t", u32);
	
	//NOTE: you need to specify size=0, or Ghidra will create empty fields in that space
	public static StructureDataType createAndGetStructureDataType(String structureName) {
		return new StructureDataType(LOADER_CATPATH, structureName, 0);
	}
	
	public static StructureDataType createAndGetStructureDataType(CategoryPath catPath, String structureName) {
		return new StructureDataType(catPath, structureName, 0);
	}
	
	/**
	 * Gets a BinaryReader that covers bytes in a MemoryBlock
	 * @param block Memory block the BinaryReader will cover
	 * @param startAddr	Start address in memory block the BinaryReader will cover from
	 * @param length Length of the buffer the BinaryReader will cover - must not be 0
	 * @return A BinaryReader that covers a length-bytes long range in block starting from startAddr
	 * @throws MemoryAccessException if underlying methods throw it
	 */
	public static BinaryReader getByteArrayBackedBinaryReader(ProcessingContext ctx, Address startAddr, int length) 
			throws MemoryAccessException {
		byte[] storage = new byte[length];
		MemoryBlock block = getMemBlockForPointer(ctx, startAddr.getUnsignedOffset());
		block.getBytes(startAddr, storage);
		ByteProvider bp = new ByteArrayProvider(storage);
		return new BinaryReader(bp, IS_LITTLE_ENDIAN);
	}
	
	public static BinaryReader getMemoryBackedBinaryReader(Memory memory, Address startAddr) {
		return new BinaryReader(new MemoryByteProvider(memory, startAddr), IS_LITTLE_ENDIAN);
	}
	
	public static ArrayDataType makeArray(DataType dt, int numElem) {
		return new ArrayDataType(dt, numElem, dt.getLength());
	}
	
	//Adds all the <scetypes.h> types into a SCE category
	public static void createSceDataTypes(DataTypeManager dtm) {
		//TODO: add the following types (probably 32-bit sized, needs check)
		/*"SceLong", ??,*/ 
		/*"SceULong", ??,*/
		Map.ofEntries(
				Map.entry("SceChar8", 		s8),
				Map.entry("SceUChar8", 		u8),
				Map.entry("SceInt8", 		s8),
				Map.entry("SceUInt8", 		u8),
				Map.entry("SceShort16", 	s16),
				Map.entry("SceUShort16", 	u16),
				Map.entry("SceInt16", 		s16),
				Map.entry("SceUInt16", 		u16),
				Map.entry("SceInt32", 		s32),
				Map.entry("SceUInt32", 		u32),
				Map.entry("SceInt", 		s32),
				Map.entry("SceUInt", 		u32), 
				Map.entry("SceInt64", 		s64),
				Map.entry("SceUInt64", 		u64),
				Map.entry("SceLong64", 		s64),
				Map.entry("SceULong64", 	u64),
				Map.entry("SceFloat", 		f32),
				Map.entry("SceFloat32", 	f32),
				Map.entry("SceDouble", 		f64),
				Map.entry("SceDouble64", 	f64),
				Map.entry("SceSByte",		s8),
				Map.entry("SceSByte8",		s8),
				Map.entry("SceByte",		u8),
				Map.entry("SceByte8",		u8),
				Map.entry("SceWChar16",		u16),
				Map.entry("SceWChar32",		u32),
				Map.entry("SceIntPtr",		s32),
				Map.entry("SceUIntPtr",		u32),
				Map.entry("ScePVoid",		PVOID),
				Map.entry("SceSize",		u32),
				Map.entry("SceSSize",		s32),
				Map.entry("SceUIntVAddr",	u32),
				Map.entry("SceUID",			s32),
				Map.entry("SceName",		new PointerDataType(s8)))
		.forEach((alias, dt) ->
				dtm.addDataType(new TypedefDataType(SCE_TYPES_CATPATH, alias, dt), 
					DataTypeConflictHandler.ConflictResolutionPolicy.REPLACE_EXISTING.getHandler())
		);
		
		//Add aliases of SCE types
		DataType SceUID = dtm.getDataType(SCE_TYPES_CATPATH, "SceUID");
		DataType SceSize = dtm.getDataType(SCE_TYPES_CATPATH, "SceSize");
		DataType SceSSize = dtm.getDataType(SCE_TYPES_CATPATH, "SceSSize");
		DataType SceInt64 = dtm.getDataType(SCE_TYPES_CATPATH, "SceInt64");
		
		Map.of( "ScePSize", 	SceSize,
				"SceVSize", 	SceSize,
				"ScePSSize", 	SceSSize,
				"SceVSSize", 	SceSSize,
				"SceOff",		SceInt64,
				"ScePID",		SceUID)
		.forEach((alias, dt) ->
				dtm.addDataType(new TypedefDataType(SCE_TYPES_CATPATH, alias, dt),
						DataTypeConflictHandler.ConflictResolutionPolicy.REPLACE_EXISTING.getHandler())
		);
				
		
		//Add common constants
		EnumDataType sceConstantsDt = new EnumDataType(SCE_TYPES_CATPATH, "SCE_CONSTANTS", u32.getLength());
		sceConstantsDt.add("SCE_NULL", 0);
		sceConstantsDt.add("SCE_OK", 0);
		sceConstantsDt.add("SCE_FALSE", 0);
		sceConstantsDt.add("SCE_TRUE", 1);
		sceConstantsDt.add("SCE_UID_INVALID_UID", 0xFFFFFFFFL);
		dtm.addDataType(sceConstantsDt, DataTypeConflictHandler.ConflictResolutionPolicy.REPLACE_EXISTING.getHandler());
	}

/*
 * Gadgets
 */
	private static MemoryBlock getMemBlockForPointer(ProcessingContext ctx, long pointer) {
		Address ret = ctx.textBlock.getStart().getNewAddress(pointer);
		if (ctx.textBlock.contains(ret)) {
			return ctx.textBlock;
		}
		ret = ctx.dataBlock.getStart().getNewAddress(pointer);
		if (ctx.dataBlock.contains(ret)) {
			return ctx.dataBlock;
		}
		ctx.logger.appendMsg(String.format("Couldn't find block containing address 0x%08X in processing context !\n\tPlease warn CreepNT.", pointer));
		return null;
	}

}
