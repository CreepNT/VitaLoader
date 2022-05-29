package vita.elf;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.ElfSymbol;
//import ghidra.app.util.bin.format.elf.ElfConstants;
//import ghidra.app.util.bin.format.elf.ElfDynamicTable;
//import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSymbolTable;
import ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.util.StringUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NoValueException;
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
		
		VitaElfHeader elfHdr = getElfHeader();
		Memory memory = getMemory();
		monitor.setMessage("Completing ELF header parsing...");
		monitor.setCancelEnabled(false);
		elfHdr.parse();
		monitor.setCancelEnabled(true);


		monitor.setMessage("Completing ELF header parsing...");
		monitor.setCancelEnabled(false);
		elfHdr.parse();
		monitor.setCancelEnabled(true);

		int id = program.startTransaction("Load ELF program");
		boolean success = false;
		try {

			addProgramProperties(monitor);

			setImageBase();
			program.setExecutableFormat(ElfLoader.ELF_NAME);

			// resolve segment/sections and create program memory blocks
			ByteProvider byteProvider = elfHdr.getReader().getByteProvider();
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

			if (elfHdr.e_shnum() == 0) {
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

			//processEntryPoints(monitor);

			processRelocations(monitor);
			processImports(monitor);

			monitor.setMessage("Processing PLT/GOT ...");
			elfHdr.getLoadAdapter().processGotPlt(this, monitor);

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
		VitaElfHeader elfHdr = getElfHeader();
		monitor.checkCanceled();
		monitor.setMessage("Adding program properties...");

		Options props = program.getOptions(Program.PROGRAM_INFO);

		// Preserve original image base which may be required for DWARF address fixup.
		// String is used to avoid decimal rendering of long values in display.
		props.setString(ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY,
			"0x" + Long.toHexString(elfHdr.getImageBase()));
		
		//Vita doesn't support prelinking, pointless to print info about it
		//props.setBoolean(ElfLoader.ELF_PRELINKED_PROPERTY, elf.isPreLinked());

		ExecutableInfo elfInfo = VitaElfHeader.EXECUTABLE_TYPES.get(elfHdr.e_type());
		if (elfInfo == null) { //wtf?
			props.setString(ElfLoader.ELF_FILE_TYPE_PROPERTY, String.format("Unknown! (0x%04X)", elfHdr.e_type()));
			props.setBoolean(RelocationTable.RELOCATABLE_PROP_NAME, false);
		} else {
			props.setString(ElfLoader.ELF_FILE_TYPE_PROPERTY, elfInfo.name + " (" + elfInfo.typeName + ")");
			props.setBoolean(RelocationTable.RELOCATABLE_PROP_NAME, elfInfo.relocatable);
		}

		//May be useless
		int fileIndex = 0;
		ElfSymbolTable[] symbolTables = elfHdr.getSymbolTables();
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
	
	/**
	 * Calculate the load address associated with a specified elfSymbol.
	 * @param elfSymbol ELF symbol
	 * @return symbol address or null if symbol not supported and address not determined,
	 * or {@link Address#NO_ADDRESS} if symbol is external and should be allocated to the EXTERNAL block.
	 */
	@SuppressWarnings("unused")
	protected Address calculateSymbolAddress(ElfSymbol elfSymbol) {

		if (elfSymbol.getSymbolTableIndex() == 0) {
			return null; // always skip the first symbol, it is NULL
		}

		if (elfSymbol.isFile()) {
			return null; //do not create file symbols... (source file list added to program properties)
		}

		if (elfSymbol.isTLS()) {
			// TODO: Investigate support for TLS symbols
			log("Unsupported Thread-Local Symbol not loaded: " + elfSymbol.getNameAsString());
			return null;
		}

		ElfLoadAdapter loadAdapter = elf.getLoadAdapter();

		// Allow extension to have first shot at calculating symbol address
		try {
			Address address = elf.getLoadAdapter().calculateSymbolAddress(this, elfSymbol);
			if (address != null) {
				return address;
			}
		}
		catch (NoValueException e) {
			return null;
		}

		ElfSectionHeader[] elfSections = elf.getSections();
		short sectionIndex = elfSymbol.getSectionHeaderIndex();
		Address symSectionBase = null;
		AddressSpace defaultSpace = getDefaultAddressSpace();
		AddressSpace defaultDataSpace = getDefaultDataSpace();
		AddressSpace symbolSpace = defaultSpace;
		long symOffset = elfSymbol.getValue();

		if (sectionIndex > 0) {
			if (sectionIndex < elfSections.length) {
				ElfSectionHeader symSection = elf.getSections()[sectionIndex];
				symSectionBase = findLoadAddress(symSection, 0);
				if (symSectionBase == null) {
					log("Unable to place symbol due to non-loaded section: " +
						elfSymbol.getNameAsString() + " - value=0x" +
						Long.toHexString(elfSymbol.getValue()) + ", section=" +
						symSection.getNameAsString());
					return null;
				}	
						
				//HACK: for some reason, in some modules, every symbol is loaded in the default address space? (0-0xFFFFFFFF)
				//The problem is that usually st_value is an offset in the segment instead of an absolute address.
				//Work around by returning  (symSectionBase + st_value) if st_value is too small.
				
				if (symOffset < 0x81000000L) {
					return symSectionBase.add(symOffset);
				}
				return symbolSpace.getTruncatedAddress(symOffset, true);
				
			} // else assume sections have been stripped
			AddressSpace space = symbolSpace.getPhysicalSpace();
			symOffset = loadAdapter.getAdjustedMemoryOffset(symOffset, space);
			if (space == defaultSpace) {
				symOffset =
					elf.adjustAddressForPrelink(symOffset) + getImageBaseWordAdjustmentOffset();
			}
			else if (space == defaultDataSpace) {
				symOffset += getImageDataBase();
			}
		}
		else if (sectionIndex == ElfSectionHeaderConstants.SHN_UNDEF) { // Not section relative 0x0000 (e.g., no sections defined)

			Address regAddr = findMemoryRegister(elfSymbol);
			if (regAddr != null) {
				return regAddr;
			}

			// FIXME: No sections defined or refers to external symbol
			// Uncertain what if any offset adjustments should apply, although the
			// EXTERNAL block is affected by the program image base
			symOffset = loadAdapter.getAdjustedMemoryOffset(symOffset, defaultSpace);
			symOffset += getImageBaseWordAdjustmentOffset();
		}
		else if (sectionIndex == ElfSectionHeaderConstants.SHN_ABS) { // Absolute value/address - 0xfff1
			// TODO: Which space ? Can't distinguish simple constant vs. data vs. code/default space
			// The should potentially be assign a constant address instead (not possible currently)

			// Note: Assume data space - symbols will be "pinned"

			// TODO: it may be inappropriate to adjust since value may not actually be a memory address - what to do?
			// symOffset = loadAdapter.adjustMemoryOffset(symOffset, space);

			Address regAddr = findMemoryRegister(elfSymbol);
			if (regAddr != null) {
				return regAddr;
			}

			symbolSpace = getConstantSpace();
		}
		else if (sectionIndex == ElfSectionHeaderConstants.SHN_COMMON) { // Common symbols - 0xfff2 (
			// TODO: Which space ? Can't distinguish data vs. code/default space
			// I believe COMMON symbols must be allocated based upon their size.  These symbols
			// during the linking phase will generally be placed into a data section (e.g., .data, .bss)

		}
		else { // TODO: Identify which cases if any that this is valid

			// SHN_LORESERVE 0xff00
			// SHN_LOPROC 0xff00
			// SHN_HIPROC 0xff1f
			// SHN_COMMON 0xfff2
			// SHN_HIRESERVE 0xffff

			log("Unable to place symbol: " + elfSymbol.getNameAsString() +
				" - value=0x" + Long.toHexString(elfSymbol.getValue()) + ", section-index=0x" +
				Integer.toHexString(sectionIndex & 0xffff));
			return null;
		}

		Address address = symbolSpace.getTruncatedAddress(symOffset, true);
		if (symbolSpace.isOverlaySpace() && address.getAddressSpace() != symbolSpace) {
			// Ensure that address remains within correct symbol space
			address = symbolSpace.getAddressInThisSpaceOnly(address.getOffset());
		}

		if (elfSymbol.isAbsolute()) {
			// TODO: Many absolute values do not refer to memory at all
			// should we exclude certain absolute symbols (e.g., 0, 1)?

			//we will just use the symbols preferred address...
		}
		else if (elfSymbol.isExternal() || elfSymbol.isCommon()) {
			return Address.NO_ADDRESS;
		}
		else if (elf.isRelocatable()) {
			if (sectionIndex < 0 || sectionIndex >= elfSections.length) {
				log("Error creating symbol: " + elfSymbol.getNameAsString() +
					" - 0x" + Long.toHexString(elfSymbol.getValue()));
				return Address.NO_ADDRESS;
			}
			else if (symSectionBase == null) {
				log("No Memory for symbol: " + elfSymbol.getNameAsString() +
					" - 0x" + Long.toHexString(elfSymbol.getValue()));
				return Address.NO_ADDRESS;
			}
			else {
				// Section relative symbol - ensure that symbol remains in
				// overlay space even if beyond bounds of associated block
				// Note: don't use symOffset variable since it may have been
				//   adjusted for image base
				address = symSectionBase.addWrapSpace(elfSymbol.getValue() *
					symSectionBase.getAddressSpace().getAddressableUnitSize());
			}
		}
		else if (!elfSymbol.isSection() && elfSymbol.getValue() == 0) {
			return Address.NO_ADDRESS;
		}
		else if (elfSymbol.getValue() == 1) {
			// Most likely a Thumb Symbol...
			return Address.NO_ADDRESS;
		}

		return address;
	}
	
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
