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
		
		//Add default SCE datatypes
		//ctx.typeDb.addSceTypes(TypeHelper.SCE_TYPES_CATPATH);
		
		//Load types database if user asked to provide one
		//ctx.typeDb.loadAndParseToProgram(ctx.helper.useExternalTypes); //No - TypeDatabase is broken
		
		//Load NIDs database
		ctx.nidDb.populate(ctx.helper.useExternalNIDs);
		
		
		Address moduleInfoAddress = null;
		if (elf.e_type() == VitaElfHeader.ET_SCE_PSP2RELEXEC) {
			//For old ELF (<= 0.931), p_phaddr of .text holds FILE OFFSET of SceModuleInfo
			//so SceModuleInfo is at .text + p_phaddr - p_offset
			
			//Set guessed SDK version
			Utils.setModuleSDKVersion(0x00931000L);
			
			ElfProgramHeader modInfoPhdr = null;
			
			ElfProgramHeader[] Phdrs = elf.getProgramHeaders();
			for (ElfProgramHeader ph: Phdrs) {
				if (ph.getPhysicalAddress() != 0) { //First w/ non-0 paddr is assumed to be .text
					modInfoPhdr = ph;
					break;
				}
			}
			
			
			if (modInfoPhdr == null) {
				throw new RuntimeException("Cannot find non-null p_paddr in Phdrs");
			}
			
			long modInfoOffset = modInfoPhdr.getPhysicalAddress() - modInfoPhdr.getOffset();
			moduleInfoAddress = Utils.getProgramAddress(modInfoOffset);
		} else { //New format (>= 0.940) - e_entry = offset
			//Set guessed SDK version
			Utils.setModuleSDKVersion(0x00940000L);
			
			moduleInfoAddress = Utils.getProgramAddress(elf.e_entry());
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
