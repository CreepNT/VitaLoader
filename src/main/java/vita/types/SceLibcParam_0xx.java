package vita.types;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.util.exception.DuplicateNameException;

import vita.misc.TypeHelper;
import vita.elf.VitaElfExtension.ProcessingContext;

public class SceLibcParam_0xx implements StructConverter {
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
	private final ProcessingContext _ctx;
	private final Address _selfAddress;
	public static final int SIZE = 0x1C;
	public static final String NAME = "SceLibcParam_0xx";
	
	public SceLibcParam_0xx(ProcessingContext ctx, Address libcParamAddress, BinaryReader reader) throws IOException {
		size = reader.readNextUnsignedInt();
		unk4 = reader.readNextUnsignedInt();
		pHeapSize = reader.readNextUnsignedInt();
		pHeapDefaultSize = reader.readNextUnsignedInt();
		pHeapExtendedAlloc = reader.readNextUnsignedInt();
		pHeapDelayedAlloc = reader.readNextUnsignedInt();
		SDKVersion = reader.readNextUnsignedInt();
		
		_ctx = ctx;
		_selfAddress = libcParamAddress;
	}
	
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}

	public void apply() throws Exception {
		StructureDataType dt = TypeHelper.createAndGetStructureDataType(NAME);
		dt.add(TypeHelper.u32, "size", "Size of this structure");
		dt.add(TypeHelper.u32, 4, "unk04", null);
		dt.add(new PointerDataType(TypeHelper.u32), "pHeapSize",  "Pointer to the allocated/maximum heap size");
		dt.add(new PointerDataType(TypeHelper.u32), "pHeapDefaultSize", "Pointer to the ?default heap size? - usage unknown");
		dt.add(new PointerDataType(TypeHelper.u32), "pHeapExtendedAlloc", "Pointer to the 'Extend heap' variable - enables dynamic heap if value pointed to is non-0");
		dt.add(new PointerDataType(TypeHelper.u32), "pHeapDelayedAlloc", "Pointer to the 'Delay heap allocation' variable - heap memory block allocation is done on first call to *alloc instead of process creation if value pointed to is non-0");
		dt.add(TypeHelper.u32, "SDKVersion", "SDK version this app was linked against");

		if (dt.getLength() != SIZE)
			System.err.println("Unexpected " + NAME + " data type size (" + dt.getLength() + " != expected " + SIZE + " !)");

		_ctx.api.clearListing(_selfAddress, _selfAddress.add(dt.getLength()));
		_ctx.api.createData(_selfAddress, dt);
		_ctx.api.createLabel(_selfAddress, _ctx.moduleName + "_SceLibcParam", true);
	}
}
