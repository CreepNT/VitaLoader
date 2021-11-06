package vita.types;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.util.exception.DuplicateNameException;
import vita.elf.VitaElfExtension.ProcessingContext;
import vita.misc.TypeHelper;

public class SceProcessParam implements StructConverter {
	public long size;
	public long magic;
	public long version;
	public long fw_version;
	public long sceUserMainThreadName;
	public long sceUserMainThreadPriority;
	public long sceUserMainThreadStackSize;
	public long sceUserMainThreadAttribute;
	public long sceProcessName;
	public long sceKernelPreloadModuleInhibit;
	public long sceUserMainThreadCpuAffinityMask;
	public long __sce_libcparam;
	public long unk;
	public static final int SIZE = 0x34;
	public static final String NAME = "SceProcessParam";

	private ProcessingContext _ctx;
	private Address _selfAddress;
	
	public SceProcessParam(ProcessingContext ctx, Address processParamAddr) throws IOException, MemoryAccessException {
		BinaryReader reader = TypeHelper.getByteArrayBackedBinaryReader(ctx, processParamAddr, SIZE);
		
		size = reader.readNextUnsignedInt();
		magic = reader.readNextUnsignedInt();
		version = reader.readNextUnsignedInt();
		fw_version = reader.readNextUnsignedInt();
		sceUserMainThreadName = reader.readNextUnsignedInt();
		sceUserMainThreadPriority = reader.readNextUnsignedInt();
		sceUserMainThreadStackSize = reader.readNextUnsignedInt();
		sceUserMainThreadAttribute = reader.readNextUnsignedInt();
		sceProcessName = reader.readNextUnsignedInt();
		sceKernelPreloadModuleInhibit = reader.readNextUnsignedInt();
		sceUserMainThreadCpuAffinityMask = reader.readNextUnsignedInt();
		__sce_libcparam = reader.readNextUnsignedInt();
		unk = reader.readNextUnsignedInt();
		
		_ctx = ctx;
		_selfAddress = processParamAddr;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}
	
	public void apply() throws Exception {
		StructureDataType dt = TypeHelper.createAndGetStructureDataType(NAME);
		dt.add(TypeHelper.u32, "size", "Size of this structure");
		dt.add(STRING, 4, "magic", "Structure magic - 'PSP2'");
		dt.add(TypeHelper.u32, "version", "Version of this structure");
		dt.add(TypeHelper.u32, "SDKVersion", "SDK version this app was linked against");
		dt.add(new PointerDataType(StringDataType.dataType), "pUserMainThreadName", "Pointer to main thread name");
		dt.add(new PointerDataType(TypeHelper.u32), "pUserMainThreadPriority", "Pointer to main thread priority");
		dt.add(new PointerDataType(TypeHelper.u32), "pUserMainThreadStackSize", "Pointer to main thread stack size");
		dt.add(new PointerDataType(TypeHelper.u32), "pUserMainThreadAttribute", "Pointer to main thread attributes");
		dt.add(new PointerDataType(StringDataType.dataType), "pProcessName", "Pointer to process name");
		dt.add(new PointerDataType(TypeHelper.u32), "pKernelPreloadModuleInhibit", "Pointer to module preload inibition variable");
		dt.add(new PointerDataType(TypeHelper.u32), "pUserMainThreadCpuAffinityMask", "Pointer to main thread CPU affinity mask");
		dt.add(Pointer32DataType.dataType, "pLibcParam", "Pointer to SceLibc parameters");
		dt.add(TypeHelper.u32, "unk30", null); //Field not present in 0.945
		
		if (dt.getLength() != SIZE)
			System.err.println("Unexpected " + NAME + " data type size (" + dt.getLength() + " != expected " + SIZE + " !)");
		
		_ctx.api.clearListing(_selfAddress, _selfAddress.add(dt.getLength()));
		_ctx.api.createData(_selfAddress, dt);
		_ctx.api.createLabel(_selfAddress, _ctx.moduleName + "_" + dt.getName(), true);
		
		
		__markup_if_present(this.sceUserMainThreadName, "sceUserMainThreadName", StringDataType.dataType);
		__markup_if_present(this.sceUserMainThreadPriority, "sceUserMainThreadPriority", TypeHelper.s32);
		__markup_if_present(this.sceUserMainThreadStackSize, "sceUserMainThreadStackSize", TypeHelper.u32);
		__markup_if_present(this.sceUserMainThreadAttribute, "sceUserMainThreadAttribute", TypeHelper.u32);
		__markup_if_present(this.sceProcessName, "sceProcessName", StringDataType.dataType);
		__markup_if_present(this.sceKernelPreloadModuleInhibit, "sceKernelPreloadModuleInhibit", TypeHelper.u32);
		__markup_if_present(this.sceUserMainThreadCpuAffinityMask, "sceUserMainThreadCpuAffinityMask", TypeHelper.u32);

		if (this.__sce_libcparam != 0L) {
			Address libcParamAddress = _ctx.textStart.getNewAddress(this.__sce_libcparam);
			BinaryReader libcParamReader = TypeHelper.getByteArrayBackedBinaryReader(_ctx, libcParamAddress, Math.max(SceLibcParam_1xx.SIZE, SceLibcParam_2xx.SIZE));
			int libcParamSize = libcParamReader.peekNextInt(); //Use peek instead of read to keep index at 0 for struct creation
			
			switch (libcParamSize) {
			case SceLibcParam_0xx.SIZE:
				new SceLibcParam_0xx(_ctx, libcParamAddress, libcParamReader).apply();
				break;
			case SceLibcParam_1xx.SIZE:
				new SceLibcParam_1xx(_ctx, libcParamAddress, libcParamReader).apply();
				break;
			case SceLibcParam_2xx.SIZE:
				new SceLibcParam_2xx(_ctx, libcParamAddress, libcParamReader).apply();
				break;
			default:
				_ctx.logger.appendMsg(String.format("Unknown SceLibcParam structure size 0x%08X at address " + libcParamAddress + ".", libcParamSize));
			}
		} else {
			_ctx.logger.appendMsg("No SceLibcParam found in SceProcessParam.");
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
