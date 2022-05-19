package vita.types;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.PointerDataType;

import vita.misc.TypeManager;
import vita.misc.Utils;

public class SceLibcParam_0xx {
	public long size;
	public long unk4;
	public long pHeapSize;
	public long pHeapDefaultSize;
	public long pHeapExtendedAlloc;
	public long pHeapDelayedAlloc;
	public long SDKVersion;
	public long unk1C;
	public long pMallocReplace;
	public long pFreeReplace;

	public static final int SIZE = 0x1C;
	public static final String NAME = "SceLibcParam_0xx";
	
	public static final CategoryPath CATPATH = new CategoryPath(TypeManager.SCE_TYPES_CATPATH, "SceLibc");
	
	public SceLibcParam_0xx(Address libcParamAddress, BinaryReader reader) throws Exception {
		size = reader.readNextUnsignedInt();
		unk4 = reader.readNextUnsignedInt();
		pHeapSize = reader.readNextUnsignedInt();
		pHeapDefaultSize = reader.readNextUnsignedInt();
		pHeapExtendedAlloc = reader.readNextUnsignedInt();
		pHeapDelayedAlloc = reader.readNextUnsignedInt();
		SDKVersion = reader.readNextUnsignedInt();
		
		if (Utils.getModuleSDKVersion() != SDKVersion) {
			Utils.appendLogMsg(String.format("Mismatched SDK version in SceLibcParam (0x%08X != 0x%08X)", SDKVersion, Utils.getModuleSDKVersion()));
		}
		
		Utils.createDataInNamespace(libcParamAddress, Utils.getModuleName(), NAME, toDataType());
	}
	
	private static StructureDataType DATATYPE = null;
	public static DataType toDataType() {
		if (DATATYPE == null) {
			final DataType SceUInt32 = TypeManager.getDataType("SceUInt32");
			
			DATATYPE = new StructureDataType(CATPATH, NAME, 0);
			DATATYPE.add(SceUInt32, "size", "Size of this structure");
			DATATYPE.add(SceUInt32, 4, "unk04", null);
			DATATYPE.add(new PointerDataType(SceUInt32), "pHeapSize",  "Pointer to the allocated/maximum heap size");
			DATATYPE.add(new PointerDataType(SceUInt32), "pHeapDefaultSize", "Pointer to the ?default heap size? - usage unknown");
			DATATYPE.add(new PointerDataType(SceUInt32), "pHeapExtendedAlloc", "Pointer to the 'Extend heap' variable - enables dynamic heap if value pointed to is non-0");
			DATATYPE.add(new PointerDataType(SceUInt32), "pHeapDelayedAlloc", "Pointer to the 'Delay heap allocation' variable - heap memory block allocation is done on first call to *alloc instead of process creation if value pointed to is non-0");
			DATATYPE.add(SceUInt32, "SDKVersion", "SDK version this app was linked against");

			if (DATATYPE.getLength() != SIZE)
				System.err.println("Unexpected " + NAME + " data type size (" + DATATYPE.getLength() + " != expected " + SIZE + " !)");
		}
		return DATATYPE;
	}

	public void apply() throws Exception {



	}
}
