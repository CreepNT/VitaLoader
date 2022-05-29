package vita.types;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.PointerDataType;

import vita.misc.TypeManager;
import vita.misc.Utils;
import vita.elf.VitaElfExtension.ProcessingContext;

public class SceLibcParam_1xx {
	public long size;
	public long unk4;
	public long pHeapSize;
	public long pHeapDefaultSize;
	public long pHeapExtendedAlloc;
	public long pHeapDelayedAlloc;
	public long sdk_version;
	public long unk1C;
	public long pMallocReplace;
	public long pFreeReplace;

	private ProcessingContext _ctx = null;
	
	public static final int SIZE = 0x28;
	public static final String NAME = "SceLibcParam_1xx";
	
	public static final CategoryPath CATPATH = new CategoryPath(TypeManager.SCE_TYPES_CATPATH, "SceLibc");
	
	//TODO: verify what malloc_replace and free_replace are (probably LibcReplace and LibcxxReplace)
	public SceLibcParam_1xx(ProcessingContext ctx, Address libcParamAddress, BinaryReader reader) throws Exception {
		_ctx = ctx;
		
		size = reader.readNextUnsignedInt();
		unk4 = reader.readNextUnsignedInt();
		pHeapSize = reader.readNextUnsignedInt();
		pHeapDefaultSize = reader.readNextUnsignedInt();
		pHeapExtendedAlloc = reader.readNextUnsignedInt();
		pHeapDelayedAlloc = reader.readNextUnsignedInt();
		sdk_version = reader.readNextUnsignedInt();
		unk1C = reader.readNextUnsignedInt();
		pMallocReplace = reader.readNextUnsignedInt();
		pFreeReplace = reader.readNextUnsignedInt();
		
		Utils.createDataInNamespace(libcParamAddress, Utils.getModuleNamespace(), "__sce_libcparam", toDataType());
		
		__markup_if_present(this.pHeapSize, "sceLibcHeapSize");
		__markup_if_present(this.pHeapDefaultSize, "__sceLibcHeapSizeDefault");
		__markup_if_present(this.pHeapExtendedAlloc, "sceLibcHeapExtendedAlloc");
		__markup_if_present(this.pHeapDelayedAlloc, "sceLibcHeapDelayedAlloc");
	}
	
	private static StructureDataType DATATYPE = null;
	public static DataType toDataType() {
		if (DATATYPE == null) {
			final DataType SceUInt32 = TypeManager.getDataType("SceUInt32");
			
			DATATYPE = new StructureDataType(CATPATH, NAME, 0);
			DATATYPE.add(SceUInt32, "size", "Size of this structure");
			DATATYPE.add(SceUInt32, "unk04", null);
			DATATYPE.add(new PointerDataType(SceUInt32), "pHeapSize",  "Pointer to the allocated/maximum heap size");
			DATATYPE.add(new PointerDataType(SceUInt32), "pHeapDefaultSize", "Pointer to the ?default heap size? - usage unknown");
			DATATYPE.add(new PointerDataType(SceUInt32), "pHeapExtendedAlloc", "Pointer to the 'Extend heap' variable - enables dynamic heap if value pointed to is non-0");
			DATATYPE.add(new PointerDataType(SceUInt32), "pHeapDelayedAlloc", "Pointer to the 'Delay heap allocation' variable - heap memory block allocation is done on first call to *alloc instead of process creation if value pointed to is non-0");
			DATATYPE.add(SceUInt32, "SDKVersion", "SDK version this app was linked against");
			DATATYPE.add(SceUInt32, "unk1C", null);
			DATATYPE.add(Pointer32DataType.dataType, "malloc_replace", null);	
			DATATYPE.add(Pointer32DataType.dataType, "free_replace", null);

			if (DATATYPE.getLength() != SIZE)
				System.err.println("Unexpected " + NAME + " data type size (" + DATATYPE.getLength() + " != expected " + SIZE + " !)");
		}
		return DATATYPE;
	}
	
	private void __markup_if_present(long address, String name) throws Exception {
		if (address != 0L)
			_ctx.api.createLabel(Utils.getProgramAddress(address), name, true, SourceType.ANALYSIS);
	}
}
