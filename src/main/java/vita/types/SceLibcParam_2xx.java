package vita.types;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.util.exception.DuplicateNameException;
import vita.elf.VitaElfExtension.ProcessingContext;
import vita.misc.TypeHelper;

public class SceLibcParam_2xx implements StructConverter {
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
	
	public SceLibcParam_2xx(ProcessingContext ctx, Address libcParamAddress, BinaryReader reader) throws IOException {
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
	}
	
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}

	public void apply() throws Exception {
		StructureDataType dt = TypeHelper.createAndGetStructureDataType(NAME);
		dt.add(TypeHelper.u32, "size", "Size of this structure");
		dt.add(TypeHelper.u32, "unk04", null);
		dt.add(new PointerDataType(TypeHelper.u32), "pHeapSize", "Pointer to the allocated/maximum heap size");
		dt.add(new PointerDataType(TypeHelper.u32), "pHeapDefaultSize", "Pointer to the ?default heap size? - usage unknown");
		dt.add(new PointerDataType(TypeHelper.u32), "pHeapExtendedAlloc", "Pointer to the 'Extend heap' variable - enables dynamic heap if value pointed to is non-0");
		dt.add(new PointerDataType(TypeHelper.u32), "pHeapDelayedAlloc", "Pointer to the 'Delay heap allocation' variable - heap memory block allocation is done on first call to *alloc instead of process creation if value pointed to is non-0");
		dt.add(TypeHelper.u32, "SDKVersion", "SDK version this app was linked against");
		dt.add(TypeHelper.u32, "unk1C", null);
		dt.add(Pointer32DataType.dataType, "__sce_libc_alloc_replace", "Pointer to replacement functions for Libc memory allocation functions");		
		dt.add(Pointer32DataType.dataType, "__sce_libcxx_alloc_replace","Pointer to replacement functions for Libcxx (C++) memory allocation functions");
		dt.add(new PointerDataType(TypeHelper.u32), "pHeapInitialSize", "Pointer to the 'Initial heap allocation size' variable - specifies the size of the memory block to allocate on process creation if dynamic heap is enabled");
		dt.add(new PointerDataType(TypeHelper.u32), "pHeapUnitSize1MiB", "Pointer to the 'Big heap block granularity' variable - memory block allocations have a 1MiB granularity if value pointed to is non-0 (default is 64KiB)");
		dt.add(new PointerDataType(TypeHelper.u32), "pHeapDetectOverrun", "Pointer to the 'Detect heap overruns' variable - enables heap checking on free/realloc if value pointed to is non-0");
		dt.add(Pointer32DataType.dataType, "__sce_libc_tls_alloc_replace", "Pointer to replacement functions for TLS memory allocation functions");

		if (dt.getLength() != SIZE)
			System.err.println("Unexpected " + NAME + " data type size (" + dt.getLength() + " != expected " + SIZE + " !)");

		_ctx.api.clearListing(_selfAddress, _selfAddress.add(dt.getLength()));
		_ctx.api.createData(_selfAddress, dt);
		_ctx.api.createLabel(_selfAddress, _ctx.moduleName + "_SceLibcParam", true);
		
		__markup_if_present(this.pHeapSize, "sceLibcHeapSize", TypeHelper.u32);
		__markup_if_present(this.pHeapDefaultSize, "__sceLibcHeapSizeDefault", TypeHelper.u32);
		__markup_if_present(this.pHeapExtendedAlloc, "sceLibcHeapExtendedAlloc", TypeHelper.u32);
		__markup_if_present(this.pHeapDelayedAlloc, "sceLibcHeapDelayedAlloc", TypeHelper.u32);
		__markup_if_present(this.pHeapInitialSize, "sceLibcHeapInitialSize", TypeHelper.u32);
		__markup_if_present(this.pHeapUnitSize1MiB, "sceLibcHeapUnitSize1MiB", TypeHelper.u32);
		__markup_if_present(this.pHeapDetectOverrun, "sceLibcHeapDetectOverrun", TypeHelper.u32);
		
		if (this.__sce_libc_alloc_replace != 0L) {
			//Read size to make sure it's valid
			Address libcAllocReplacementAddress = _ctx.textStart.getNewAddress(__sce_libc_alloc_replace);
			BinaryReader libcAllocReplacementReader = TypeHelper.getByteArrayBackedBinaryReader(_ctx, libcAllocReplacementAddress, LibcAllocReplacement.SIZE);
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
			Address libcxxAllocReplacementAddress = _ctx.textStart.getNewAddress(__sce_libcxx_alloc_replace);
			BinaryReader libcxxAllocReplacementReader = TypeHelper.getByteArrayBackedBinaryReader(_ctx, libcxxAllocReplacementAddress, LibcxxAllocReplacement.SIZE);
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
			Address tlsAllocReplacementAddress = _ctx.textStart.getNewAddress(__sce_libc_tls_alloc_replace);
			BinaryReader tlsAllocReplacementReader = TypeHelper.getByteArrayBackedBinaryReader(_ctx, tlsAllocReplacementAddress, TlsAllocReplacement.SIZE);
			int tlsAllocReplacementSize = tlsAllocReplacementReader.peekNextInt();//Use peek instead of read to keep index at 0 for struct creation
			
			switch (tlsAllocReplacementSize) {
			case TlsAllocReplacement.SIZE:
				new TlsAllocReplacement(_ctx, tlsAllocReplacementAddress, tlsAllocReplacementReader).apply();
				break;
			default:
				_ctx.logger.appendMsg(String.format("Unknown " + TlsAllocReplacement.NAME +  " size 0x%08X at address " + tlsAllocReplacementAddress + " .", tlsAllocReplacementSize));
				break;
			}
		}
	}
	
	private void __markup_if_present(long address, String name, DataType datatype) throws Exception {
		if (address != 0L) {
			Address addr = _ctx.textStart.getNewAddress(address);
			_ctx.api.clearListing(addr, addr.add(datatype.getLength()));
			_ctx.api.createLabel(addr, name, true, SourceType.ANALYSIS);
			_ctx.api.createData(addr, datatype);
		}
	}
}

