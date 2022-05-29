package vita.types;


import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.PointerDataType;
import vita.elf.VitaElfExtension.ProcessingContext;

import vita.misc.TypeManager;
import vita.misc.Utils;

public class SceLibcParam_2xx {
	public long size;
	public long unk04;
	public long pHeapSize;
	public long pHeapDefaultSize;
	public long pHeapExtendedAlloc;
	public long pHeapDelayedAlloc;
	public long sdk_version;
	public long unk1C;
	public long __sce_libc_alloc_replace;
	public long __sce_libcxx_alloc_replace;
	public long pHeapInitialSize;
	public long pHeapUnitSize1MiB;
	public long pHeapDetectOverrun;
	public long __sce_libc_tls_alloc_replace;
	private final ProcessingContext _ctx;
	private final Address _selfAddress;
	public static final int SIZE = 0x38;
	public static final String NAME = "SceLibcParam_2xx";
	
	public static final CategoryPath CATPATH = new CategoryPath(TypeManager.SCE_TYPES_CATPATH, "SceLibc");
	
	public SceLibcParam_2xx(ProcessingContext ctx, Address libcParamAddress, BinaryReader reader) throws Exception {
		size = reader.readNextUnsignedInt();
		unk04 = reader.readNextUnsignedInt();
		pHeapSize = reader.readNextUnsignedInt();
		pHeapDefaultSize = reader.readNextUnsignedInt();
		pHeapExtendedAlloc = reader.readNextUnsignedInt();
		pHeapDelayedAlloc = reader.readNextUnsignedInt();
		sdk_version = reader.readNextUnsignedInt();
		unk1C = reader.readNextUnsignedInt();
		__sce_libc_alloc_replace = reader.readNextUnsignedInt();
		__sce_libcxx_alloc_replace = reader.readNextUnsignedInt();
		pHeapInitialSize = reader.readNextUnsignedInt();
		pHeapUnitSize1MiB = reader.readNextUnsignedInt();
		pHeapDetectOverrun = reader.readNextUnsignedInt();
		__sce_libc_tls_alloc_replace = reader.readNextUnsignedInt();
		
		_ctx = ctx;
		_selfAddress = libcParamAddress;
		
		Utils.createDataInNamespace(_selfAddress, Utils.getModuleNamespace(), "__sce_libcparam", toDataType());
	}
	
	private static StructureDataType DATATYPE = null;
	public static DataType toDataType() {
		if (DATATYPE == null) {
			final DataType SceUInt32 = TypeManager.getDataType("SceUInt32");
			
			DATATYPE = new StructureDataType(CATPATH, NAME, 0);
			DATATYPE.add(SceUInt32, "size", "Size of this structure");
			DATATYPE.add(SceUInt32, "unk04", null);
			DATATYPE.add(new PointerDataType(SceUInt32), "pHeapSize", "Pointer to the allocated/maximum heap size");
			DATATYPE.add(new PointerDataType(SceUInt32), "pHeapDefaultSize", "Pointer to the ?default heap size? - usage unknown");
			DATATYPE.add(new PointerDataType(SceUInt32), "pHeapExtendedAlloc", "Pointer to the 'Extend heap' variable - enables dynamic heap if value pointed to is non-0");
			DATATYPE.add(new PointerDataType(SceUInt32), "pHeapDelayedAlloc", "Pointer to the 'Delay heap allocation' variable - heap memory block allocation is done on first call to *alloc instead of process creation if value pointed to is non-0");
			DATATYPE.add(SceUInt32, "SDKVersion", "SDK version this app was linked against");
			DATATYPE.add(SceUInt32, "unk1C", null);
			DATATYPE.add(Pointer32DataType.dataType, "__sce_libc_alloc_replace", "Pointer to replacement functions for Libc memory allocation functions");		
			DATATYPE.add(Pointer32DataType.dataType, "__sce_libcxx_alloc_replace","Pointer to replacement functions for Libcxx (C++) memory allocation functions");
			DATATYPE.add(new PointerDataType(SceUInt32), "pHeapInitialSize", "Pointer to the 'Initial heap allocation size' variable - specifies the size of the memory block to allocate on process creation if dynamic heap is enabled");
			DATATYPE.add(new PointerDataType(SceUInt32), "pHeapUnitSize1MiB", "Pointer to the 'Big heap block granularity' variable - memory block allocations have a 1MiB granularity if value pointed to is non-0 (default is 64KiB)");
			DATATYPE.add(new PointerDataType(SceUInt32), "pHeapDetectOverrun", "Pointer to the 'Detect heap overruns' variable - enables heap checking on free/realloc if value pointed to is non-0");
			DATATYPE.add(Pointer32DataType.dataType, "__sce_libc_tls_alloc_replace", "Pointer to replacement functions for TLS memory allocation functions");
	
			if (DATATYPE.getLength() != SIZE)
				System.err.println("Unexpected " + NAME + " data type size (" + DATATYPE.getLength() + " != expected " + SIZE + " !)");
		}
		return DATATYPE;
	}

	public void process() throws Exception {
		final DataType SceUInt32 = TypeManager.getDataType("SceUInt32");
		
		__markup_if_present(this.pHeapSize, "sceLibcHeapSize", SceUInt32);
		__markup_if_present(this.pHeapDefaultSize, "__sceLibcHeapSizeDefault", SceUInt32);
		__markup_if_present(this.pHeapExtendedAlloc, "sceLibcHeapExtendedAlloc", SceUInt32);
		__markup_if_present(this.pHeapDelayedAlloc, "sceLibcHeapDelayedAlloc", SceUInt32);
		__markup_if_present(this.pHeapInitialSize, "sceLibcHeapInitialSize", SceUInt32);
		__markup_if_present(this.pHeapUnitSize1MiB, "sceLibcHeapUnitSize1MiB", SceUInt32);
		__markup_if_present(this.pHeapDetectOverrun, "sceLibcHeapDetectOverrun", SceUInt32);
		
		if (this.__sce_libc_alloc_replace != 0L) {
			//Read size to make sure it's valid
			Address libcAllocReplacementAddress = Utils.getProgramAddress(__sce_libc_alloc_replace);
			BinaryReader libcAllocReplacementReader = Utils.getMemoryReader(libcAllocReplacementAddress);
			int libcAllocReplacementSize = libcAllocReplacementReader.peekNextInt();//Use peek instead of read to keep index at 0 for struct creation
			
			switch (libcAllocReplacementSize) {
			case LibcAllocReplacement.SIZE:
				new LibcAllocReplacement(_ctx, libcAllocReplacementAddress, libcAllocReplacementReader).apply();
				break;
			default:
				_ctx.logger.appendMsg(String.format("Unknown " + LibcAllocReplacement.NAME + " size 0x%08X at address " + libcAllocReplacementAddress + " .", libcAllocReplacementSize));
				break;
			}
		}
		
		if (this.__sce_libcxx_alloc_replace != 0L) {
			//Read size to make sure it's valid
			Address libcxxAllocReplacementAddress = Utils.getProgramAddress(__sce_libcxx_alloc_replace);
			BinaryReader libcxxAllocReplacementReader = Utils.getMemoryReader(libcxxAllocReplacementAddress);
			int libcxxAllocReplacementSize = libcxxAllocReplacementReader.peekNextInt(); //Use peek instead of read to keep index at 0 for struct creation
			
			switch (libcxxAllocReplacementSize) {
			case LibcxxAllocReplacement.SIZE:
				new LibcxxAllocReplacement(_ctx, libcxxAllocReplacementAddress, libcxxAllocReplacementReader).apply();
				break;
			default:
				_ctx.logger.appendMsg(String.format("Unknown " + LibcxxAllocReplacement.NAME + " size 0x%08X at address " + libcxxAllocReplacementAddress + " .", libcxxAllocReplacementSize));
				break;
			}
		}
		if (this.__sce_libc_tls_alloc_replace != 0L) {
			//Read size to make sure it's valid
			Address tlsAllocReplacementAddress = Utils.getProgramAddress(__sce_libc_tls_alloc_replace);
			BinaryReader tlsAllocReplacementReader = Utils.getMemoryReader(tlsAllocReplacementAddress);
			int tlsAllocReplacementSize = tlsAllocReplacementReader.peekNextInt();//Use peek instead of read to keep index at 0 for struct creation
			
			switch (tlsAllocReplacementSize) {
			case TlsAllocReplacement.SIZE:
				new TlsAllocReplacement(_ctx, tlsAllocReplacementAddress, tlsAllocReplacementReader);
				break;
			default:
				_ctx.logger.appendMsg(String.format("Unknown " + TlsAllocReplacement.NAME +  " size 0x%08X at address " + tlsAllocReplacementAddress + " .", tlsAllocReplacementSize));
				break;
			}
		}
	}
	
	private void __markup_if_present(long address, String name, DataType datatype) throws Exception {
		if (address != 0L) {
			Utils.createDataInNamespace(Utils.getProgramAddress(address), Utils.getModuleNamespace(), name, datatype);
		}
	}
}

