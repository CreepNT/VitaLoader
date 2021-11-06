package vita.elf;

import ghidra.util.task.TaskMonitor;
import ghidra.program.model.mem.Memory;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.util.exception.CancelledException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.program.model.data.DataTypeManager;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.extend.ElfExtension;

import vita.types.SceModuleInfo;

import vita.misc.TypeHelper;
import vita.misc.NIDDatabase;
import vita.misc.TypeDatabase;

public class VitaElfExtension extends ElfExtension {
	//TODO: Fix Super Duper Ugly Hack
	public VitaElfExtension() {}
	
	//NOTE:
	//If you have a 0x81000000 ptr, then get an Address with block.getStart().getNewAddress(ptr)
	
	//Structure to hold ELF processing context
	public class ProcessingContext {
		public final VitaElfProgramBuilder helper;	
		public final MemoryBlock textBlock; //.text block
		public final MemoryBlock dataBlock;	//.data block
		public final TaskMonitor monitor;
		public final DataTypeManager dtm;	//Result of program.getDataTypeManager();
		public final FlatProgramAPI api;	//Result of new FlatProgramAPI(program);
		public final Address textStart;		//Start address of the .text block
		public final Address dataStart;		//Start address of the .data block
		public final MessageLog logger;
		public final Program program;		//Result of ElfLoadHelper.getProgram();
		public final Memory memory;			//Result of program.getMemory();
		
		public final TypeDatabase typeDb;
		public final NIDDatabase nidDb;
		
		public String moduleName; //Added by SceModuleInfo in its constructor
		
		public ProcessingContext (TaskMonitor monitor, VitaElfProgramBuilder helper){
			this.moduleName = "Paradox ERR"; //Placeholder to avoid NullPointerException, even though it should never happen
		
			this.helper 	= helper;
			this.monitor 	= monitor;
			this.logger 	= helper.getLog();
			this.program 	= helper.getProgram();
			this.memory 	= this.program.getMemory();
			this.dtm 		= this.program.getDataTypeManager();
			this.api		= new FlatProgramAPI(this.program);
			
			this.dataBlock 	= getRWMemBlock(this.memory);
			this.textBlock	= getExecutableMemBlock(this.memory);
			this.textStart  = this.textBlock.getStart();
			if (this.dataBlock != null) {
				this.dataStart  = this.dataBlock.getStart();
			} else {
				this.dataStart = this.textStart;
			}
			
			this.typeDb = new TypeDatabase(this);
			this.nidDb = new NIDDatabase(this);
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
		VitaElfProgramBuilder programBuilder = (VitaElfProgramBuilder)helper;
		VitaElfHeader elf = (VitaElfHeader)helper.getElfHeader();
		ProcessingContext ctx = new ProcessingContext(monitor, programBuilder);
		
		//Add default SCE datatypes
		ctx.typeDb.addSceTypes(TypeHelper.SCE_TYPES_CATPATH);
		
		//Load types database if user asked to provide one
		//ctx.typeDb.loadAndParseToProgram(ctx.helper.useExternalTypes); //No - TypeDatabase is broken
		
		//Load NIDs database
		ctx.nidDb.populate(ctx.helper.useExternalNIDs);
		
		//e_entry in ELF header holds offset to SceModuleInfo
		Address SceModuleInfoAddress = ctx.textStart.add(elf.e_entry());
		try {
			SceModuleInfo modInfo = new SceModuleInfo(ctx, SceModuleInfoAddress);
			modInfo.apply();
			modInfo.process();
		} catch (Exception e) {
			ctx.logger.appendException(e);
		}
		
		//Set compiler name (arbitrarily, just for fun :D)
		ctx.program.setCompiler("SNC");
		
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
