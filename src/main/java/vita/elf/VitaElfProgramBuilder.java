package vita.elf;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
//import ghidra.app.util.bin.format.elf.ElfConstants;
//import ghidra.app.util.bin.format.elf.ElfDynamicTable;
//import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSymbolTable;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.util.StringUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import vita.elf.VitaElfHeader.ExecutableInfo;
import vita.loader.VitaLoader;
import ghidra.app.util.opinion.DefaultElfProgramBuilder;

public class VitaElfProgramBuilder extends DefaultElfProgramBuilder {
	public boolean useExternalNIDs = false;
	public boolean useExternalTypes = false;
	
	
	protected VitaElfProgramBuilder(VitaElfHeader elf, Program program, List<Option> options,
			MessageLog log) {
		super(elf, program, options, log);
	}
	
	public static void loadElf(VitaElfHeader elf, Program program, List<Option> options, MessageLog log,
			TaskMonitor monitor) throws IOException, CancelledException {
		VitaElfProgramBuilder elfProgramBuilder = new VitaElfProgramBuilder(elf, program, options, log);
		elfProgramBuilder.load(monitor);
	}
	
	@Override
	public VitaElfHeader getElfHeader() {
		return (VitaElfHeader)super.getElfHeader();
	}
	
	//We need to override the load method with top-level class (ElfBuilder) method because else the other overridden methods don't seem to get called
	//Probably because DefaultElfProgramBuilder calls top-level through invoke() - it works so I'm not fixing it
	@Override
	protected void load(TaskMonitor monitor) throws IOException, CancelledException {
		//Parse Vita-specific options
		this.useExternalTypes = getBooleanOption(VitaLoader.USE_CUSTOM_TYPES_DATABASE_OPTNAME);
		this.useExternalNIDs = getBooleanOption(VitaLoader.USE_CUSTOM_NIDS_DATABASE_OPTNAME);
		
		VitaElfHeader elf = getElfHeader();
		Memory memory = getMemory();
		monitor.setMessage("Completing ELF header parsing...");
		monitor.setCancelEnabled(false);
		elf.parse();
		monitor.setCancelEnabled(true);


		monitor.setMessage("Completing ELF header parsing...");
		monitor.setCancelEnabled(false);
		elf.parse();
		monitor.setCancelEnabled(true);

		int id = program.startTransaction("Load ELF program");
		boolean success = false;
		try {

			addProgramProperties(monitor);

			setImageBase();
			program.setExecutableFormat(ElfLoader.ELF_NAME);

			// resolve segment/sections and create program memory blocks
			ByteProvider byteProvider = elf.getReader().getByteProvider();
			try (InputStream fileIn = byteProvider.getInputStream(0)) {
				fileBytes = program.getMemory()
						.createFileBytes(byteProvider.getName(), 0, byteProvider.length(), fileIn,
							monitor);
			}

			adjustSegmentAndSectionFileAllocations(byteProvider);

			// process headers and define "section" within memory elfProgramBuilder
			processProgramHeaders(monitor);
			processSectionHeaders(monitor);

			resolve(monitor);

			if (elf.e_shnum() == 0) {
				// create/expand segments to their fullsize if no sections are defined
				expandProgramHeaderBlocks(monitor);
			}

			if (memory.isEmpty()) {
				// TODO: Does this really happen?
				success = true;
				return;
			}

			markupElfHeader(monitor);
			markupProgramHeaders(monitor);
			markupSectionHeaders(monitor);
			markupDynamicTable(monitor);
			markupInterpreter(monitor);

			processStringTables(monitor);

			processSymbolTables(monitor);

			new VitaElfExtension().processElf(this, monitor);

			processEntryPoints(monitor);

			processRelocations(monitor);
			processImports(monitor);

			monitor.setMessage("Processing PLT/GOT ...");
			elf.getLoadAdapter().processGotPlt(this, monitor);

			markupHashTable(monitor);
			markupGnuHashTable(monitor);
			markupGnuBuildId(monitor);
			markupGnuDebugLink(monitor);

			processGNU(monitor);
			processGNU_readOnly(monitor);

			success = true;
		}
		finally {
			program.endTransaction(id, success);
		}
	}
	
	@Override	
	protected void addProgramProperties(TaskMonitor monitor) throws CancelledException {
		VitaElfHeader elf = getElfHeader();
		monitor.checkCanceled();
		monitor.setMessage("Adding program properties...");

		Options props = program.getOptions(Program.PROGRAM_INFO);

		// Preserve original image base which may be required for DWARF address fixup.
		// String is used to avoid decimal rendering of long values in display.
		props.setString(ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY,
			"0x" + Long.toHexString(elf.getImageBase()));
		
		//Vita doesn't support prelinking, pointless to print info about it
		//props.setBoolean(ElfLoader.ELF_PRELINKED_PROPERTY, elf.isPreLinked());

		ExecutableInfo elfInfo = VitaElfHeader.EXECUTABLE_TYPES.get(elf.e_type());
		if (elfInfo == null) { //wtf?
			props.setString(ElfLoader.ELF_FILE_TYPE_PROPERTY, String.format("Unknown! (0x%04X)", elf.e_type()));
			props.setBoolean(RelocationTable.RELOCATABLE_PROP_NAME, false);
		} else {
			props.setString(ElfLoader.ELF_FILE_TYPE_PROPERTY, elfInfo.name + " (" + elfInfo.typeName + ")");
			props.setBoolean(RelocationTable.RELOCATABLE_PROP_NAME, elfInfo.relocatable);
		}

		//May be useless
		int fileIndex = 0;
		ElfSymbolTable[] symbolTables = elf.getSymbolTables();
		for (ElfSymbolTable symbolTable : symbolTables) {
			monitor.checkCanceled();
			String[] files = symbolTable.getSourceFiles();
			for (String file : files) {
				monitor.checkCanceled();
				props.setString(ElfLoader.ELF_SOURCE_FILE_PROPERTY_PREFIX + pad(fileIndex++) + "]",
					file);
			}
		}
		
		//Vita ELFs should never have dynamic tables
		//We could parse imports here however :D
		/*
		int libraryIndex = 0;
		ElfDynamicTable dynamicTable = elf.getDynamicTable();
		if (dynamicTable != null) {
			String[] neededLibs = elf.getDynamicLibraryNames();
			for (String neededLib : neededLibs) {
				monitor.checkCanceled();
				props.setString(
					ElfLoader.ELF_REQUIRED_LIBRARY_PROPERTY_PREFIX + pad(libraryIndex++) + "]",
					neededLib);
			}
		}
		*/

	}
	
	//TODO: override createExternalFunctionLinkage? check it out for PROPER library linking
	
	private boolean getBooleanOption(String optionName) {
		for (Option option : this.options) {
			if (option.getName().equals(optionName) && Boolean.class.isAssignableFrom(option.getValueClass())) {
				return (boolean)option.getValue();
			}
		}
		return false;
	}
	
	protected String pad(int value) {
		return StringUtilities.pad("" + value, ' ', 4);
	}
}
