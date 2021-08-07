package vita.elf;


import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.extend.ElfExtension;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import vita.types.*;
import vita.misc.NIDDatabase;
import vita.misc.NIDDatabase.DatabaseType;
import vita.misc.TypesManager;

public class VitaElfExtension extends ElfExtension {
	//TODO: Fix Super Duper Ugly Hack
	public VitaElfExtension() {}
	
	//NOTE:
	//If you have a 0x81000000 ptr, then get an Address with block.getStart().getNewAddress(ptr)
	
	//Structure to hold ELF processing context
	public class ProcessingContext {
		public ExternalManager extMan;	//
		public ElfLoadHelper helper;	
		public DataTypeManager dtm;		//Result of program.getDataTypeManager();
		public TaskMonitor monitor;
		public FlatProgramAPI api;		//Result of new FlatProgramAPI(program);
		public String moduleName;		//Added by SceModuleInfo in its constructor
		public MessageLog logger;
		public MemoryBlock textBlock; 	//.text block
		public MemoryBlock dataBlock;	//.data block
		public Program program;			//Result of ElfLoadHelper.getProgram();
		public Memory memory;			//Result of program.getMemory();
		

		
		public ProcessingContext() {}
		public ProcessingContext (TaskMonitor monitor, ElfLoadHelper helper, MemoryBlock textBlock, MemoryBlock dataBlock){
			this.helper 	= helper;
			this.monitor 	= monitor;
			this.textBlock	= textBlock;
			this.dataBlock 	= dataBlock;
			this.logger 	= helper.getLog();
			this.program 	= helper.getProgram();
			this.memory 	= this.program.getMemory();
			this.dtm 		= this.program.getDataTypeManager();
			this.api		= new FlatProgramAPI(this.program);
			this.extMan 	= null;
			this.moduleName = "(Paradox Error)"; //Placeholder to avoid NullPointerException, even though it should never happen
		}
		
		public void Cleanup() {
			logger = null;
			monitor = null;
			program = null;
			memory = null;
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
		VitaElfHeader elf = (VitaElfHeader)helper.getElfHeader();
		Memory memory = helper.getProgram().getMemory();
		MemoryBlock textBlock = getExecutableMemBlock(memory); 	//.text block
		MemoryBlock dataBlock = getRWMemBlock(memory);			//.data block
		ProcessingContext ctx = new ProcessingContext(monitor, helper, textBlock, dataBlock);
		
		//e_entry in ELF header holds offset to SceModuleInfo
		Address SceModuleInfoAddress = textBlock.getStart().add(elf.e_entry());
		try {
			SceModuleInfo modInfo = new SceModuleInfo(ctx, SceModuleInfoAddress);
			modInfo.apply();
			modInfo.process();
		} catch (Exception e) {
			ctx.logger.appendException(e);
		}
		
		//Add default SCE datatypes
		TypesManager.createSceDataTypes(helper.getProgram().getDataTypeManager());
		
		//Set compiler name (arbitrarily, just for fun :D)
		ctx.program.setCompiler("SNC");
		
		if (NIDDatabase.getDatabaseType() == DatabaseType.DATABASE_NONE) {
			ctx.logger.appendMsg("Couldn't load any NID database - default names used instead.");
		}
	}
			
/*
 * Gadgets
 */
	private MemoryBlock getExecutableMemBlock(Memory mem) {
		for (MemoryBlock block : mem.getBlocks()) {
			if (block.isExecute())
				return block;
		}
		return null;
	}

	private MemoryBlock getRWMemBlock(Memory mem) {
		for (MemoryBlock block : mem.getBlocks()) {
			if (block.isRead() && block.isWrite())
				return block;
		}
		return null;
	}
}
