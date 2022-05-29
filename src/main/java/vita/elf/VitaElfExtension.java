package vita.elf;

import ghidra.util.task.TaskMonitor;
import ghidra.program.model.mem.Memory;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.util.exception.CancelledException;


import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.program.model.data.DataTypeManager;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.ElfProgramHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.extend.ElfExtension;

import vita.types.SceModuleInfo;

import vita.misc.TypeManager;
import vita.misc.Utils;
import vita.misc.NIDDatabase;

public class VitaElfExtension extends ElfExtension {
	//TODO: Fix Super Duper Ugly Hack
	public VitaElfExtension() {}
	
	//Structure to hold ELF processing context
	//TODO make this cleaner please!
	public class ProcessingContext {
		public final VitaElfProgramBuilder helper;
		public final TaskMonitor monitor;
		public final DataTypeManager dtm;	//Result of program.getDataTypeManager();
		public final FlatProgramAPI api;	//Result of new FlatProgramAPI(program);
		public final MessageLog logger;
		public final Program program;		//Result of ElfLoadHelper.getProgram();
		public final Memory memory;			//Result of program.getMemory();
		public final ProgramContext progContext;
		
		//public final TypeDatabase typeDb;
		public final NIDDatabase nidDb;
		
		public String moduleName; //Added by SceModuleInfo in its constructor
		public long SDKVersion = 0;
		
		
		public ProcessingContext (TaskMonitor monitor, VitaElfProgramBuilder helper){
			this.moduleName = "Paradox ERR"; //Placeholder to avoid NullPointerException, even though it should never happen
		
			this.helper 	= helper;
			this.monitor 	= monitor;
			this.logger 	= helper.getLog();
			this.program 	= helper.getProgram();
			this.memory 	= this.program.getMemory();
			this.dtm 		= this.program.getDataTypeManager();
			this.api		= new FlatProgramAPI(this.program);
			
			this.nidDb = new NIDDatabase(this);
			this.progContext = program.getProgramContext();
			

		}
	}
	
	@Override
	public boolean canHandle(ElfHeader elf) {
		System.out.println("canHandle()");
		return elf instanceof VitaElfHeader;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		System.out.println("canHandle(ElfLoadHelper)");
		return canHandle(elfLoadHelper.getElfHeader());
	}

	@Override
	public String getDataTypeSuffix() {
		System.out.println("getDataTypeSuffix()");
		return null;
	}
	
	@Override
	public void processElf(ElfLoadHelper helper, TaskMonitor monitor) throws CancelledException {
		Utils.setMonitorMessage(monitor, "Parsing Vita module info...");
		
		if (!(helper instanceof VitaElfProgramBuilder)) {
			throw new RuntimeException("Only VitaElfProgramBuilder is accepted!");
		}
		
		VitaElfProgramBuilder programBuilder = (VitaElfProgramBuilder)helper;
		VitaElfHeader elf = programBuilder.getElfHeader();
		
		ProcessingContext ctx = new ProcessingContext(monitor, programBuilder);
		
		Utils.initialize(ctx);
		
		TypeManager.initialize();

		//Load NIDs database
		ctx.nidDb.populate(ctx.helper.useExternalNIDs);
		
		Address moduleInfoAddress = null;
		if (elf.e_shnum() > 0) { //"Unstripped" ELF - find SceModuleInfo section
			ElfSectionHeader[] sections = elf.getSections();
			for (ElfSectionHeader section: sections) {
				if (section.getNameAsString().equals(".sceModuleInfo.rodata")) {
					moduleInfoAddress = Utils.getProgramAddress(section.getAddress());
				}
			}
		}
		
		/*

		 *	For ET SCE RELEXEC executables, the segment containing sce module info is indexed by
		 *	the upper two bits of e entry of the ELF header. The structure is stored at the base of the
		 *	segment plus the offset defined by the bottom 30 bits of e entry.
		 */

		if (elf.e_type() == VitaElfHeader.ET_SCE_PSP2RELEXEC) { //Only 0.931 is known to use this format
			Utils.setModuleSDKVersion(0x00931000L);
		} else {
			Utils.setModuleSDKVersion(0x00940000L); //Very low estimate - may be bumped up later on and should work fine overall
		}
		
		ElfProgramHeader[] Phdrs = elf.getProgramHeaders();
		
		if (moduleInfoAddress == null) { //No SceModuleInfo section - find another way
			/*
			 * For ET_SCE_PSP2RELEXEC, module info is always stored in the first segment.
			 * The location of the SceModuleInfo is stored as a FILE OFFSET in the first segment's p_paddr.
			 * 
			 * Thus, its location in memory is p_vaddr + p_paddr - p_offset.
			 * 
			 * The same applies to *some* ET_SCE_EXEC files, too - so try this first.
			 */
			ElfProgramHeader modInfoPhdr = null;
			for (ElfProgramHeader ph: Phdrs) {
				if (ph.getPhysicalAddress() != 0) { //First w/ non-0 paddr is assumed to be .text
					modInfoPhdr = ph;
					break;
				}
			}
			
			if (modInfoPhdr != null) {
				moduleInfoAddress = Utils.getProgramAddress(modInfoPhdr.getVirtualAddress() + modInfoPhdr.getPhysicalAddress() - modInfoPhdr.getOffset());
			} else {
				//No luck finding it - try the other method.
				/*
				 * For ET_SCE_RELEXEC and some ET_SCE_EXEC, all information is encoded in the EHdr.e_entry field.
				 * The top two bits encode the segment in which it resides, and the bottom 30 bits are the offset within this segment.
				 * 
				 * Thus, the location of the SceModuleInfo is PHdrs[e_entry >> 30].p_vaddr + (e_entry & 0x3FFFFFFF).
				 */
				
				int moduleInfoSegment = (int)((elf.e_entry() >> 30L) & 0x3L);
				long moduleInfoOffset = elf.e_entry() & 0x3FFFFFFFL;
				
				if (moduleInfoSegment > Phdrs.length) {
					throw new RuntimeException(String.format("Malformed ELF: e_entry = 0x%08lX indicates SceModuleInfo resides in segment %d, but there are only %d segments!", 
									elf.e_entry(), moduleInfoSegment, Phdrs.length));
				}
				
				modInfoPhdr = Phdrs[moduleInfoSegment];
				moduleInfoAddress = Utils.getProgramAddress(modInfoPhdr.getVirtualAddress() + moduleInfoOffset);				
			}
		}
		
		
		if (moduleInfoAddress == null) {
			throw new RuntimeException("Cannot find SceModuleInfo of file!");
		}
		
		try {
			SceModuleInfo modInfo = new SceModuleInfo(ctx, moduleInfoAddress);
			modInfo.process();
		} catch (Exception e) {
			ctx.logger.appendException(e);
		}
		

		//Set compiler name (arbitrarily, just for fun :D)
		ctx.program.setCompiler("SNC");
	}
}
