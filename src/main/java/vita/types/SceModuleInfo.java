package vita.types;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.program.model.mem.MemoryAccessException;

import vita.misc.TypesManager;
import vita.elf.VitaElfExtension.ProcessingContext;

public class SceModuleInfo implements StructConverter {
	public short attributes;
	public short version;
	public String name;
	public byte type;
	public long gp_value;
	public long export_top;
	public long export_end;
	public long import_top;
	public long import_end;
	public long dbg_fingerprint;
	public long tls_start;
	public long tls_filesz;
	public long tls_memsz;
	public long module_start;
	public long module_stop;
	public long exidx_top;
	public long exidx_end;
	public long extab_top;
	public long extab_end;
	public static final int SIZE = 0x5c;
	public static final String NAME = "SceModuleInfo";

	private ProcessingContext _ctx;
	private Address _selfAddress;
	
	public SceModuleInfo(ProcessingContext ctx, Address moduleInfoAddress) throws IOException, MemoryAccessException {
		BinaryReader reader = TypesManager.getByteArrayBackedBinaryReader(ctx, moduleInfoAddress, SIZE);
		attributes = reader.readNextShort();
		version = reader.readNextShort();
		name = reader.readNextAsciiString(27);
		type = reader.readNextByte();
		gp_value = reader.readNextUnsignedInt();
		export_top = reader.readNextUnsignedInt();
		export_end = reader.readNextUnsignedInt();
		import_top = reader.readNextUnsignedInt();
		import_end = reader.readNextUnsignedInt();
		dbg_fingerprint = reader.readNextUnsignedInt();
		tls_start = reader.readNextUnsignedInt();
		tls_filesz = reader.readNextUnsignedInt();
		tls_memsz = reader.readNextUnsignedInt();
		module_start = reader.readNextUnsignedInt();
		module_stop = reader.readNextUnsignedInt();
		exidx_top = reader.readNextUnsignedInt();
		exidx_end = reader.readNextUnsignedInt();
		extab_top = reader.readNextUnsignedInt();
		extab_end = reader.readNextUnsignedInt();
		
		ctx.moduleName = name;
		_ctx = ctx;
		_selfAddress = moduleInfoAddress;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}
	
	public void apply() throws Exception {
		StructureDataType dt = TypesManager.createAndGetStructureDataType(NAME);
		dt.add(WORD, "attributes", null);
		dt.add(WORD, "version", null);
		dt.add(STRING, 27, "moduleName", "Name of this module");
		dt.add(BYTE, "type", null);
		dt.add(Pointer32DataType.dataType, "gp_value", "Value for gp register (unused)");
		dt.add(IBO32, "exportsStart", "Address of exports table start");
		dt.add(IBO32, "exportsEnd", "Address of exports table end");
		dt.add(IBO32, "importsTop", "Address of imports table start");
		dt.add(IBO32, "importsEnd", "Address of imports table end");
		dt.add(DWORD, "debugFingerprint", "Unique number used for debugging");
		dt.add(IBO32, "tlsStart", "Address of TLS section start");
		dt.add(DWORD, "tlsFileSize", "Size of the TLS section in file");
		dt.add(DWORD, "tlsMemSize", "Size of the TLS section in memory");
		dt.add(IBO32, "module_start", "Address of the module_start function");
		dt.add(IBO32, "module_stop", "Address of the module_stop function");
		dt.add(IBO32, "exidx_top", "ARM EABI-style exception tables");
		dt.add(IBO32, "exidx_end", null);
		dt.add(IBO32, "extab_start", null);
		dt.add(IBO32, "extab_end", null);
		
		if (dt.getLength() != SIZE)
			System.err.println("Unexpected " + NAME + " data type size (" + dt.getLength() + " != expected " + SIZE + " !)");
		
		
		_ctx.api.clearListing(_selfAddress, _selfAddress.add(dt.getLength()));
		_ctx.api.createData(_selfAddress, dt);
		_ctx.api.createLabel(_selfAddress, this.name + "_" + dt.getName(), true);
	}
	
	public void process() throws Exception {
		//Process exports
		_ctx.monitor.setMessage("Resolving module exports...");
		Address exportsStart = _ctx.textBlock.getStart().add(export_top);
		Address exportsEnd = _ctx.textBlock.getStart().add(export_end);
		while (!exportsStart.equals(exportsEnd)) {
			SceModuleExports exportsInfo = new SceModuleExports(_ctx, exportsStart);
			if (exportsInfo.size != SceModuleExports.SIZE) {
				_ctx.logger.appendMsg("Unexpected " + SceModuleExports.NAME + " size at address " + 
						exportsStart + String.format(" (got 0x%X, expected 0x%X)", exportsInfo.size, SceModuleExports.SIZE));
				break;
			}
			exportsInfo.apply();
			exportsInfo.process();
			
			exportsStart = exportsStart.add(exportsInfo.size);
		}
		_ctx.monitor.setShowProgressValue(false);
		
		 
		//Process imports
		_ctx.monitor.setMessage("Resolving module imports...");
		Address importsStart = _ctx.textBlock.getStart().add(import_top);
		Address importsEnd = _ctx.textBlock.getStart().add(import_end);
		
		while (!importsStart.equals(importsEnd)) {
			BinaryReader importsSizeReader = TypesManager.getByteArrayBackedBinaryReader(_ctx, importsStart, 2);
			int importsSize = importsSizeReader.peekNextShort(); //Use peek instead of read to have index at 0 for struct creation
			GenericModuleImports importsObject = null;
			switch (importsSize) {
			case SceModuleImports_1xx.SIZE:
				SceModuleImports_1xx modImports1xx = new SceModuleImports_1xx(_ctx, importsStart);
				modImports1xx.apply();
				importsObject = new GenericModuleImports(_ctx, modImports1xx);
				break;
			case SceModuleImports_3xx.SIZE:
				SceModuleImports_3xx modImports3xx = new SceModuleImports_3xx(_ctx, importsStart);
				modImports3xx.apply();
				importsObject = new GenericModuleImports(_ctx, modImports3xx);
				break;
			default:
				_ctx.logger.appendMsg(String.format("Unexpected SceModuleImports size 0x%08X at address " + importsStart, importsSize));
				return;
			}
			//Process the generic imports object built in switch case
			importsObject.process();

			importsStart = importsStart.add(importsSize);
		}
				
	}

}
