package vita.types;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.PointerDataType;
import vita.elf.VitaElfExtension.ProcessingContext;
import vita.misc.TypeManager;
import vita.misc.Utils;

public class SceProcessParam {
	public long size;
	public long magic;
	public long version;
	public long sdkVersion;
	public long sceUserMainThreadName;
	public long sceUserMainThreadPriority;
	public long sceUserMainThreadStackSize;
	public long sceUserMainThreadAttribute;
	public long sceProcessName;
	public long sceKernelPreloadModuleInhibit;
	public long sceUserMainThreadCpuAffinityMask;
	public long __sce_libcparam;
	
	public long unk30 = 0; //Not present in 0.945

	
	public static final String STRUCTURE_NAME = "SceProcessParam";
	
	private ProcessingContext _ctx;
	private Address _selfAddress;
	
	public SceProcessParam(ProcessingContext ctx, Address processParamAddr) throws IOException {
		_ctx = ctx;
		_selfAddress = processParamAddr;
		
		BinaryReader reader = Utils.getMemoryReader(_selfAddress);
		
		size = reader.readNextUnsignedInt();
		magic = reader.readNextUnsignedInt();
		version = reader.readNextUnsignedInt();
		sdkVersion = reader.readNextUnsignedInt();
		sceUserMainThreadName = reader.readNextUnsignedInt();
		sceUserMainThreadPriority = reader.readNextUnsignedInt();
		sceUserMainThreadStackSize = reader.readNextUnsignedInt();
		sceUserMainThreadAttribute = reader.readNextUnsignedInt();
		sceProcessName = reader.readNextUnsignedInt();
		sceKernelPreloadModuleInhibit = reader.readNextUnsignedInt();
		sceUserMainThreadCpuAffinityMask = reader.readNextUnsignedInt();
		__sce_libcparam = reader.readNextUnsignedInt();
		
		//We're gonna cheat a bit - since we now read the SDK version
		//set it directly to ensure that the following check is precise
		Utils.setModuleSDKVersion(sdkVersion);
		
		if (size == 0x34) {
			unk30 = reader.readNextUnsignedInt();
		} else if (size != 0x30) {
			throw new RuntimeException("Unsupported SceProcessParam size " + size);
		}
	}
	
	public DataType toDataType() {
		final DataType SceUInt32 = TypeManager.getDataType("SceUInt32");
		
		StructureDataType dt = new StructureDataType(TypeManager.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);
		dt.add(SceUInt32, "size", "Size of this structure");
		dt.add(Utils.makeArray(CharDataType.dataType, 4), "magic", "Structure magic - 'PSP2'");
		dt.add(SceUInt32, "version", "Version of this structure");
		dt.add(SceUInt32, "SDKVersion", "SDK version this app was linked against");
		dt.add(new PointerDataType(CharDataType.dataType), "pUserMainThreadName", "Pointer to main thread name");
		dt.add(new PointerDataType(SceUInt32), "pUserMainThreadPriority", "Pointer to main thread priority");
		dt.add(new PointerDataType(SceUInt32), "pUserMainThreadStackSize", "Pointer to main thread stack size");
		dt.add(new PointerDataType(SceUInt32), "pUserMainThreadAttribute", "Pointer to main thread attributes");
		dt.add(new PointerDataType(CharDataType.dataType), "pProcessName", "Pointer to process name");
		dt.add(new PointerDataType(SceUInt32), "pKernelPreloadModuleInhibit", "Pointer to module preload inibition variable");
		dt.add(new PointerDataType(SceUInt32), "pUserMainThreadCpuAffinityMask", "Pointer to main thread CPU affinity mask");
		dt.add(Pointer32DataType.dataType, "pLibcParam", "Pointer to SceLibc parameters");
		
		if (size == 0x34) {
			dt.add(SceUInt32, "unk30", null);
		}
		
		return dt;

	}
	
	public void apply() throws Exception {
		final DataType SceUInt32 = TypeManager.getDataType("SceUInt32");
		
		Utils.createDataInNamespace(_selfAddress, Utils.getModuleNamespace(), "__sce_process_param", toDataType());
		
		markup_string_if_present(this.sceUserMainThreadName, "sceUserMainThreadName");
		markup_if_present(this.sceUserMainThreadPriority, "sceUserMainThreadPriority", SceUInt32);
		markup_if_present(this.sceUserMainThreadStackSize, "sceUserMainThreadStackSize", SceUInt32);
		markup_if_present(this.sceUserMainThreadAttribute, "sceUserMainThreadAttribute", SceUInt32);
		markup_string_if_present(this.sceProcessName, "sceProcessName");
		markup_if_present(this.sceKernelPreloadModuleInhibit, "sceKernelPreloadModuleInhibit", SceUInt32);
		markup_if_present(this.sceUserMainThreadCpuAffinityMask, "sceUserMainThreadCpuAffinityMask", SceUInt32);

		if (this.__sce_libcparam != 0L) {
			Address libcParamAddress = Utils.getProgramAddress(this.__sce_libcparam);
			BinaryReader libcParamReader = Utils.getMemoryReader(libcParamAddress);
			int libcParamSize = libcParamReader.peekNextInt(); //Use peek instead of read to keep index at 0 for struct creation
			
			switch (libcParamSize) {
			case SceLibcParam_0xx.SIZE:
				new SceLibcParam_0xx(libcParamAddress, libcParamReader).apply();
				break;
			case SceLibcParam_1xx.SIZE:
				new SceLibcParam_1xx(_ctx, libcParamAddress, libcParamReader);
				break;
			case SceLibcParam_2xx.SIZE:
				new SceLibcParam_2xx(_ctx, libcParamAddress, libcParamReader).process();
				break;
			default:
				_ctx.logger.appendMsg(String.format("Unknown SceLibcParam structure size 0x%08X at address " + libcParamAddress + ".", libcParamSize));
			}
		} else {
			_ctx.logger.appendMsg("No SceLibcParam found in SceProcessParam.");
		}
	}
	
	private void markup_if_present(long address, String name, DataType datatype) throws Exception {
		if (address != 0L) {
			Utils.createDataInNamespace(Utils.getProgramAddress(address), Utils.getModuleNamespace(), name, datatype);
		}
	}
	
	private void markup_string_if_present(long address, String name) throws Exception {
		if (address != 0L) {
			Utils.createDataInNamespace(Utils.getProgramAddress(address), Utils.getModuleNamespace(), name, new TerminatedStringDataType());
		}
	}
}
