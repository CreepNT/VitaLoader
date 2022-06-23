package vita.elf;

import java.util.Map;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;

/**
 * Known values (from psp2bin):
 * 0xFE00 = ET_SCE_EXEC
 * 0xFE04 = ET_SCE_RELEXEC (PRX)
 * 0xFE0C = ET_SCE_STUBLIB (Stub library)
 * 0xFE10 = ET_SCE_DYNEXEC (Main module - ASLR)
 * 0xFE18 = ET_SCE_DYNAMIC (PRX)
 * 0xFFA0 = ET_SCE_PSPRELEXEC
 * 0xFFA4 = ET_SCE_PPURELEXEC
 *
 * Only 0xFE00, 0xFE04 and 0xFFA5 have been in use on Vita
 */
public class VitaElfHeader extends ElfHeader {
	public static class ExecutableInfo {
		public ExecutableInfo(int _e_type, String _typeName, String _name, boolean _relocatable) {
			e_type = (short)_e_type;
			name = _name;
			typeName = _typeName;
			relocatable = _relocatable;
		}
		
		public final short e_type;
		public final String typeName;
		public final String name;
		public final boolean relocatable;
	}
	
	public static final short ET_REL = (short)0x0001;
	public static final short ET_EXEC = (short)0x0002;
	public static final short ET_CORE = (short)0x0004;
	public static final short ET_SCE_EXEC = (short)0xFE00;
	public static final short ET_SCE_RELEXEC = (short)0xFE04;
	public static final short ET_SCE_PSP2RELEXEC = (short)0xFFA5;
	
	public static final Map<Short, ExecutableInfo> EXECUTABLE_TYPES = Map.of(
			ET_REL, new ExecutableInfo(ET_REL, "ET_REL", "Standard relocatable ELF", true),
			ET_EXEC, new ExecutableInfo(ET_EXEC, "ET_EXEC", "Standard executable ELF", false),
			ET_CORE, new ExecutableInfo(ET_CORE, "ET_CORE", "Standard ELF corefile", false),
			ET_SCE_EXEC, new ExecutableInfo(ET_SCE_EXEC, "ET_SCE_RELEXEC", "SCE Executable", false),
			ET_SCE_RELEXEC, new ExecutableInfo(ET_SCE_RELEXEC, "ET_SCE_RELEXEC", "SCE Relocatable Executable", true),
			ET_SCE_PSP2RELEXEC, new ExecutableInfo(ET_SCE_PSP2RELEXEC, "ET_SCE_PSP2RELEXEC", "PSP2 Relocatable Executable", true) //Guessed name - present in old modules
    );
	
	public static final short ARM_MACHINE_TYPE = (short)0x28; //e_machine value for ARM
	
	//TODO - override parse() so that the correct extension (i.e. VitaElfExtension) is created
	
	public static VitaElfHeader createElfHeader(GenericFactory factory, ByteProvider provider)
			throws ElfException {
		VitaElfHeader elfHeader = (VitaElfHeader)factory.create(VitaElfHeader.class);
		elfHeader.initElfHeader(factory, provider);
		
		if (elfHeader.e_machine() != ARM_MACHINE_TYPE) {
			throw new ElfException("Invalid e_machine");
		}
		
		if (!EXECUTABLE_TYPES.containsKey(elfHeader.e_type())) {
			throw new ElfException("Invalid e_type");
		}
		
		return elfHeader;
	}
}
