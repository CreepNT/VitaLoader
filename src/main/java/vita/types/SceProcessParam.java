package vita.types;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.util.exception.DuplicateNameException;
import vita.elf.VitaElfExtension.ProcessingContext;
import vita.misc.TypesManager;

public class SceProcessParam implements StructConverter {
	public long size;
	public long magic;
	public long version;
	public long fw_version;
	public long main_thread_name;
	public long main_thread_priority;
	public long main_thread_stacksize;
	public long main_thread_attribute;
	public long process_name;
	public long process_preload_disabled;
	public long main_thread_cpu_affinity_mask;
	public long sce_libc_param;
	public long unk;
	public static final int SIZE = 0x34;
	public static final String NAME = "SceProcessParam";

	private ProcessingContext _ctx;
	private Address _selfAddress;
	
	public SceProcessParam(ProcessingContext ctx, Address processParamAddr) throws IOException, MemoryAccessException {
		BinaryReader reader = TypesManager.getByteArrayBackedBinaryReader(ctx, processParamAddr, SIZE);
		
		size = reader.readNextUnsignedInt();
		magic = reader.readNextUnsignedInt();
		version = reader.readNextUnsignedInt();
		fw_version = reader.readNextUnsignedInt();
		main_thread_name = reader.readNextUnsignedInt();
		main_thread_priority = reader.readNextUnsignedInt();
		main_thread_stacksize = reader.readNextUnsignedInt();
		main_thread_attribute = reader.readNextUnsignedInt();
		process_name = reader.readNextUnsignedInt();
		process_preload_disabled = reader.readNextUnsignedInt();
		main_thread_cpu_affinity_mask = reader.readNextUnsignedInt();
		sce_libc_param = reader.readNextUnsignedInt();
		unk = reader.readNextUnsignedInt();
		
		_ctx = ctx;
		_selfAddress = processParamAddr;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}
	
	public void apply() throws Exception {
		StructureDataType dt = TypesManager.createAndGetStructureDataType(NAME);
		dt.add(DWORD, "size", "Size of this structure");
		dt.add(STRING, 4, "magic", "PSP2");
		dt.add(DWORD, "version", null);
		dt.add(DWORD, "fw_version", "SDK Version this process was compiled with");
		dt.add(Pointer32DataType.dataType, "main_thread_name", "Pointer to name of mainthread");
		dt.add(DWORD, "main_thread_priority", "Priority value of the main thread");
		dt.add(DWORD, "main_thread_stacksize", "Stack size of the main thread");
		dt.add(DWORD, "main_thread_attributes", null);
		dt.add(Pointer32DataType.dataType, "process_name", null);
		dt.add(DWORD, "process_preload_disabled", null);
		dt.add(DWORD, "main_thread_cpu_affinity_mask", "Affinity mask of the main thread");
		dt.add(Pointer32DataType.dataType, "pLibcParam", "Pointer to libc parameters");
		dt.add(DWORD, "unk", null);
		
		if (dt.getLength() != SIZE)
			System.err.println("Unexpected " + NAME + " data type size (" + dt.getLength() + " != expected " + SIZE + " !)");
		
		_ctx.api.clearListing(_selfAddress, _selfAddress.add(dt.getLength()));
		_ctx.api.createData(_selfAddress, dt);
		_ctx.api.createLabel(_selfAddress, _ctx.moduleName + "_" + dt.getName(), true);
		
		if (this.main_thread_name != 0L)
			_ctx.api.createLabel(_ctx.textBlock.getStart().getNewAddress(this.main_thread_name), _ctx.moduleName + "_main_thread_name", true);
		if (this.process_name != 0L)
			_ctx.api.createLabel(_ctx.textBlock.getStart().getNewAddress(this.process_name), _ctx.moduleName + "_process_name", true);

		if (this.sce_libc_param == 0L) {
			_ctx.logger.appendMsg("No libc param found in process param.");
			return;
		}
		
		Address libcParamAddress = _ctx.textBlock.getStart().getNewAddress(this.sce_libc_param);
		BinaryReader libcParamReader = TypesManager.getByteArrayBackedBinaryReader(_ctx, libcParamAddress, Math.max(SceLibcParam_1xx.SIZE, SceLibcParam_2xx.SIZE));
		int libcParamSize = libcParamReader.peekNextInt(); //Use peek instead of read to keep index at 0 for struct creation
		
		//TODO: refactor SceLibcParam - works for now so it'll be fine
		switch (libcParamSize) {
		case SceLibcParam_1xx.SIZE:
			new SceLibcParam_1xx(libcParamReader).apply(_ctx, libcParamAddress, _ctx.moduleName);
			return;
		case SceLibcParam_2xx.SIZE:
			new SceLibcParam_2xx(libcParamReader).apply(_ctx, libcParamAddress, _ctx.moduleName);
			return;
		default:
			_ctx.logger.appendMsg(String.format("Unknown SceLibcParam structure size 0x%08X at address " + libcParamAddress + ".", libcParamSize));
			return;
		}
	}
}
