package vita.misc;


import java.nio.ByteOrder;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.SignedByteDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import vita.elf.VitaElfExtension.ProcessingContext;

public class TypeHelper {
	//Category all structures created through the TypesManager will be stored under
	private final static CategoryPath LOADER_CATPATH = new CategoryPath("/VitaLoader");
	
	//Category all the base SCE data types will be stored under
	public final static CategoryPath SCE_TYPES_CATPATH = new CategoryPath("/SCE");
	
	//Category all types from the database will be stored under
	public final static CategoryPath TYPES_DB_CATPATH = new CategoryPath("/DBTypes");
	
	//Used for bytes manipulation functions
	private final static boolean IS_LITTLE_ENDIAN = true;
	public final static ByteOrder BYTE_ORDER = IS_LITTLE_ENDIAN ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;
	
	//Aliases of primitive types, for convenience
	public final static DataType PVOID = new Pointer32DataType(StructConverter.VOID);
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
	public final static DataType size_t = new TypedefDataType(new CategoryPath("/stddef.h"), "size_t", u32);
	
	public static StructureDataType createAndGetStructureDataType(String structureName) {
		//NOTE: you need to specify size=0, or Ghidra will create empty fields in that space
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
	 * @throws MemoryAccessException
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
	
/*
 * Gadgets
 */
	private static MemoryBlock getMemBlockForPointer(ProcessingContext ctx, long pointer) {
		Address ret = ctx.textStart.getNewAddress(pointer);
		if (ctx.textBlock.contains(ret)) {
			return ctx.textBlock;
		}
		ret = ctx.dataStart.getNewAddress(pointer);
		if (ctx.dataBlock.contains(ret)) {
			return ctx.dataBlock;
		}
		ctx.logger.appendMsg(String.format("Couldn't find block containing address 0x%08X in processing context !\n\tPlease warn CreepNT.", pointer));
		return null;
	}

}
