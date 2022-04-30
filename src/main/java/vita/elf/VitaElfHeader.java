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
	
	public static final Map<Short, ExecutableInfo> EXECUTABLE_TYPES = Map.of(
			(short)0xFE00, new ExecutableInfo(0xFE00, "ET_SCE_RELEXEC", "SCE Executable", false),
			(short)0xFE04, new ExecutableInfo(0xFE04, "ET_SCE_RELEXEC", "SCE Relocatable Executable", true)//, //ET_SCE_RELEXEC
			//TODO support this
			//(short)0xFFA5, new ExecutableInfo(0xFFA5, "ET_SCE_PSP2RELEXEC", "PSP2 Relocatable Executable", true) //Guessed name - present in old modules
    );
	
	
	public static final short ARM_MACHINE_TYPE 		= (short)0x28; 	 //e_machine value for ARM - expected for PS Vita ELFs
	
	/*
	public static final short ET_SCE_EXEC 			= (short)0xFE00; //e_type value for non-relocatable images
	public static final String ET_SCE_EXEC_NAME 	= "SCE Executable";

	public static final short ET_SCE_RELEXEC 		= (short)0xFE04; //e_type value for relocatable images (PRX)
	public static final String ET_SCE_RELEXEC_NAME 	= "SCE Relocatable Executable";
	
	public static final short ET_SCE_PSP2RELEXEC 	= (short)0xFFA5; //e_type value for old modules (0.931/some 0.940) - name is guessed
	public static final String ET_SCE_PSP2RELEXEC_NAME = "SCE PSP2 Relocatable Executable";
	*/
	
	
	
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
