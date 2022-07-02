package vita.types;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Pointer32DataType;
import vita.misc.TypeManager;
import vita.misc.Utils;
import vita.elf.VitaElfExtension.ProcessingContext;

public class SceModuleInfo {
	public short attributes = 0;
	public short[] version = { 0, 0 };
	public String modname = "";
	public byte infover = 0;
	public long gp_value = 0;
	public long libent_top = 0;
	public long libent_btm = 0;
	public long libstub_top = 0;
	public long libstub_btm = 0;
	public long fingerprint = 0;
	
	public long start_entry = 0;
	public long stop_entry = 0;
	
	public long tls_top= 0;
	public long tls_filesz = 0;
	public long tls_memsz = 0;

	public long exidx_top = 0;
	public long exidx_btm = 0;
	public long extab_top = 0;
	public long extab_btm = 0;
	public static final String STRUCTURE_NAME = "SceModuleInfo";

	private static DataType MODULE_ATTRIBUTES = null;
	private StructureDataType STRUCTURE = null;
	
	private ProcessingContext _ctx;
	private Address _selfAddress;
	
	public SceModuleInfo(ProcessingContext ctx, Address moduleInfoAddress) throws Exception {
		_ctx = ctx;
		_selfAddress = moduleInfoAddress;
		
		BinaryReader reader = Utils.getMemoryReader(moduleInfoAddress);
		attributes = reader.readNextShort();
		version[0] = reader.readNextByte();
		version[1] = reader.readNextByte();
		
		byte[] rawModname = reader.readByteArray(reader.getPointerIndex(), 27);
		int nulIdx = -1;
		for (int i = 0; i < rawModname.length; i++) {
			if (rawModname[i] == '\0') {
				nulIdx = i;
				break;
			}
		}
		
		if (nulIdx == -1) {
			throw new RuntimeException("SceModuleInfo is malformed! Are you sure this is a valid PS Vita ELF?");
		}

		modname = reader.readNextAsciiString(27);
		
		infover = reader.readNextByte();

		//Fields common to all versions
		gp_value = reader.readNextUnsignedInt();
		libent_top = reader.readNextUnsignedInt();
		libent_btm = reader.readNextUnsignedInt();
		libstub_top = reader.readNextUnsignedInt();
		libstub_btm = reader.readNextUnsignedInt();
		
		if (gp_value != 0) {
			_ctx.logger.appendMsg(String.format("Unexpected gp_value 0x%08X - are you sure this is a Vita ELF?", gp_value));
		}
		
		if (infover == 0) {
			throw new RuntimeException("SceModuleInfo with infover 0 is not supported!");
		}
		
		fingerprint = reader.readNextUnsignedInt();
		
		//Change according to version
		if (infover < 6) {
			if (infover >= 1) { //v1 fields
				start_entry = reader.readNextUnsignedInt();
				stop_entry = reader.readNextUnsignedInt();
			}
			
			if (infover >= 2) { //v2 fields
				exidx_top = reader.readNextUnsignedInt();
				exidx_btm = reader.readNextUnsignedInt();
			}
			
			if (infover == 3) { //v3 fields
				tls_top = reader.readNextUnsignedInt();
				tls_filesz = reader.readNextUnsignedInt();
				tls_memsz = reader.readNextUnsignedInt();
			}
			
			if (infover > 3) {
				throw new RuntimeException("SceModuleInfo with infover 4/5 is not supported!");
			}
		} else {
			if (infover > 6) {
				throw new RuntimeException("SceModuleInfo with infover > 6 is not supported!");
			}
			
			tls_top = reader.readNextUnsignedInt();
			tls_filesz = reader.readNextUnsignedInt();
			tls_memsz = reader.readNextUnsignedInt();
			start_entry = reader.readNextUnsignedInt();
			stop_entry = reader.readNextUnsignedInt();
			exidx_top = reader.readNextUnsignedInt();
			exidx_btm = reader.readNextUnsignedInt();
			extab_top = reader.readNextUnsignedInt();
			extab_btm = reader.readNextUnsignedInt();
		}
		
		_ctx.moduleName = modname;
		
		Utils.createDataInNamespace(_selfAddress, Utils.getModuleNamespace(), "__sce_moduleinfo", this.toDataType());
	}
	
	public DataType toDataType() {
		if (MODULE_ATTRIBUTES == null) {
			EnumDataType attr = new EnumDataType(TypeManager.SCE_TYPES_CATPATH, "MODULE_ATTRIBUTES", 2);
			attr.add("SCE_MODULE_ATTR_NONE", 			0x0000, "No module attributes");
			attr.add("SCE_MODULE_ATTR_CANT_STOP", 		0x0001, "Resident module - cannot be stopped or unloaded.");
			attr.add("SCE_MODULE_ATTR_EXCLUSIVE_LOAD",  0x0002, "Only one instance of this module can be loaded at a time.");
			attr.add("SCE_MODULE_ATTR_EXCLUSIVE_START", 0x0004, "Only one instance of this module can be started at a time.");
			attr.add("SCE_MODULE_ATTR_CAN_RESTART",     0x0008, "?Module can be restarted after being stopped?");
			attr.add("SCE_MODULE_ATTR_CAN_RELOCATE",    0x0010, "?Module can be relocated?");
			attr.add("SCE_MODULE_ATTR_CANT_SHARE",      0x0020, "?Module cannot be shared?");
			attr.add("SCE_MODULE_ATTR_DEBUG", 			0x0800, "Debug");
			MODULE_ATTRIBUTES = attr;
		}
		
		if (STRUCTURE == null) {
			final DataType IBO32 = TypeManager.IBO32;
			
			STRUCTURE = new StructureDataType(TypeManager.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);
			STRUCTURE.add(MODULE_ATTRIBUTES, "modattr", "Module attributes");
			STRUCTURE.add(Utils.makeArray(TypeManager.getDataType("SceUInt8"), 2), "modver", "Module version ([0] = major, [1] = minor)");
			STRUCTURE.add(Utils.makeArray(CharDataType.dataType, 27), "modname", "Module name");
			STRUCTURE.add(TypeManager.getDataType("SceUInt8"), "infover", "SceModuleInfo version");
			STRUCTURE.add(Pointer32DataType.dataType, "gp_value", "Value for the gp register (unused)");
			STRUCTURE.add(IBO32, "libent_top", "Address of exports table top");
			STRUCTURE.add(IBO32, "libent_end", "Address of exports table bottom");
			STRUCTURE.add(IBO32, "libstub_top", "Address of imports table top");
			STRUCTURE.add(IBO32, "libstub_end", "Address of imports table bottom");
			STRUCTURE.add(TypeManager.getDataType("SceUInt32"), "fingerprint", "Module fingerprint");
			
			
			
			//Change according to version
			if (infover < 6) {
				if (infover >= 1) { //v1 fields
					STRUCTURE.add(IBO32, "start_entry", "Address of the module_start entrypoint");
					STRUCTURE.add(IBO32, "stop_entry", "Address of the module_stop entrypoint");
				}
				
				if (infover >= 2) { //v2 fields
					STRUCTURE.add(IBO32, "exidx_top", "ARM EABI exception index table top");
					STRUCTURE.add(IBO32, "exidx_btm", "ARM EABI exception index table bottom");
				}
				
				if (infover == 3) { //v3 fields
					STRUCTURE.add(IBO32, "tls_start", "Address of TLS section start");
					STRUCTURE.add(TypeManager.getDataType("SceSize"), "tls_file_size", "Size of the TLS section in file");
					STRUCTURE.add(TypeManager.getDataType("SceSize"), "tls_mem_size", "Size of the TLS section in memory");
				}
			} else {
				STRUCTURE.add(IBO32, "tls_top", "TLS top");
				STRUCTURE.add(TypeManager.getDataType("SceSize"), "tls_file_size", "Size of the TLS section in file");
				STRUCTURE.add(TypeManager.getDataType("SceSize"), "tls_mem_size", "Size of the TLS section in memory");
				STRUCTURE.add(IBO32, "start_entry", "Address of the module_start entrypoint");
				STRUCTURE.add(IBO32, "stop_entry", "Address of the module_stop entrypoint");
				STRUCTURE.add(IBO32, "exidx_top", "ARM EABI exception index table top");
				STRUCTURE.add(IBO32, "exidx_btm", "ARM EABI exception index table bottom");
				STRUCTURE.add(IBO32, "extab_start", "ARM EABI exception table top");
				STRUCTURE.add(IBO32, "extab_end", "ARM EABI exception table bottom");
			}
			
			//Utils.registerDataType(STRUCTURE);
		}
		
		//Utils.registerDataType(STRUCTURE);
		
		return STRUCTURE;
	}

	public void process() throws Exception {
		//Process exports
		_ctx.monitor.setMessage("Resolving module exports...");
		Address exportsStart = Utils.getProgramAddress(libent_top);
		Address exportsEnd = Utils.getProgramAddress(libent_btm);
		while (exportsStart.compareTo(exportsEnd) < 0) {
			SceLibEntryTable exportsInfo = new SceLibEntryTable(_ctx, exportsStart);
			exportsInfo.process();
			
			exportsStart = exportsStart.add(exportsInfo.size);
		}
		
		if (!exportsStart.equals(exportsEnd)) {
			throw new RuntimeException("Mismatched exports parsing - ended at " + exportsStart.toString() + " instead of expected " + exportsEnd.toString());
		}
		
		_ctx.monitor.setShowProgressValue(false);
		
		 
		//Process imports
		_ctx.monitor.setMessage("Resolving module imports...");
		Address importsStart = Utils.getProgramAddress(libstub_top);
		Address importsEnd = Utils.getProgramAddress(libstub_btm);
		
		while (importsStart.compareTo(importsEnd) < 0) {
			int importsSize = Utils.getMemoryReader(importsStart).readNextShort();
			GenericModuleImports importsObject = null;
			switch (importsSize) {
			case SceLibStubTable_0x34.STRUCTURE_SIZE:
				importsObject = new GenericModuleImports(_ctx, new SceLibStubTable_0x34(importsStart));
				break;
			case SceLibStubTable_0x24.STRUCTURE_SIZE:
				importsObject = new GenericModuleImports(_ctx, new SceLibStubTable_0x24(importsStart));
				break;
			case SceLibStubTable_0x2C.STRUCTURE_SIZE:
				importsObject = new GenericModuleImports(_ctx, new SceLibStubTable_0x2C(importsStart));
				break;
			default:
				_ctx.logger.appendMsg(String.format("Unexpected SceModuleImports size 0x%08X at address " + importsStart, importsSize));
				return;
			}
			//Process the generic imports object built in switch case
			importsObject.process();

			importsStart = importsStart.add(importsSize);
		}
		
		if (!importsStart.equals(importsEnd)) {
			throw new RuntimeException("Mismatched imports parsing - ended at " + importsStart.toString() + " instead of expected " + importsEnd.toString());
		}	
	}

}
