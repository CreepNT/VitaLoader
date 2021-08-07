package vita.elf;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;

public class VitaElfHeader extends ElfHeader {
	public static final short ARM_MACHINE_TYPE 	= (short)0x28; 	 //e_machine value for ARM - expected for PS Vita ELFs
	public static final short ET_SCE_EXEC 		= (short)0xFE00; //e_type value for non-relocatable images
	public static final String ET_SCE_EXEC_NAME = "SCE Executable";
	public static final short ET_SCE_RELEXEC	= (short)0xFE04; //e_type value for relocatable images
	public static final String ET_SCE_RELEXEC_NAME = "SCE Relocatable Executable";
	
	public static VitaElfHeader createElfHeader(GenericFactory factory, ByteProvider provider)
			throws ElfException {
		VitaElfHeader elfHeader = (VitaElfHeader)factory.create(VitaElfHeader.class);
		elfHeader.initElfHeader(factory, provider);
		return elfHeader;
	}
}
