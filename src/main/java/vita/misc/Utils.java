package vita.misc;

import java.math.BigInteger;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import vita.elf.VitaElfExtension.ProcessingContext;

public class Utils {
	public static RegisterValue ThumbTMode;
	public static RegisterValue ARMTMode;

	private static ProcessingContext utilsCtx;
	
	public static void initialize(ProcessingContext ctx) {
		utilsCtx = ctx;
		
		Register TMode = utilsCtx.progContext.getRegister("TMode");
		ARMTMode = new RegisterValue(TMode, BigInteger.ZERO);
		ThumbTMode = new RegisterValue(TMode, BigInteger.ONE);
	}
	
	public static Namespace getModuleNamespace() throws DuplicateNameException, InvalidInputException {
		if (utilsCtx.moduleName == null) {
			throw new RuntimeException("NO MODULE NAME!!!!");
		}
		
		return getNamespaceFromName("##" + utilsCtx.moduleName);
	}
	
	
	public static MemoryBlock findBlockForAddress(Address addr) {
		MemoryBlock[] blocks = utilsCtx.memory.getBlocks();
		for (MemoryBlock block : blocks) {
			Address start = block.getStart();
			Address end = block.getEnd();
			
			if ((start.compareTo(addr) <= 0) && (end.compareTo(addr) > 0)) {
				return block;
			}
		}
		
		return null;
	}
	
	
	public static MemoryBlock findBlockForAddress(long addr) {
		MemoryBlock[] blocks = utilsCtx.memory.getBlocks();
		for (MemoryBlock block : blocks) {
			if (block.isOverlay() || block.isMapped()) {
				continue;
			}
			
			long start = block.getStart().getOffset();
			long end = block.getEnd().getOffset();
			
			if ((start <= addr) && (addr < end)) {
				return block;
			}
		}
		
		return null;
	}
	
	public static void getBytes(Address addr, byte[] buffer) throws MemoryAccessException {
		MemoryBlock mb = findBlockForAddress(addr);
		if (mb == null) {
			throw new RuntimeException("Can't find memblock for address " + addr.toString());
		}
		mb.getBytes(addr, buffer);
	}
	
	public static Address getProgramAddressUnchecked(long location) {
		final long imageBase = utilsCtx.helper.getElfHeader().getImageBase();
		long vaddress = location;
		
		MemoryBlock block = findBlockForAddress(vaddress);
		if (block == null) { //Try as a RVA instead of absolute vaddress
			vaddress = imageBase + location;
			if ((block = findBlockForAddress(vaddress)) == null) {
				return null;
			}
		}
		
		final long blockBase = block.getStart().getOffset();
		return block.getStart().add(vaddress - blockBase);
	}
	
	public static Address getProgramAddress(long location) {
		Address addr = getProgramAddressUnchecked(location);
		if (addr == null) {
			throw new RuntimeException(String.format("Cannot obtain Address object for location 0x%08X", location));
		}
		 return addr;
	}
	
	public static void registerDataType(DataType dt) {
		utilsCtx.dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
	}
	
	public static DataType makeArray(DataType dt, int numElem) {
		return new ArrayDataType(dt, numElem, dt.getLength());
	}
	
	/**
	 * Creates a namespace in Global namespace if non-existent, else returns the existing one.
	 * @param name  Name of the new namespace
	 * @return New namespace
	 * @throws DuplicateNameException
	 * @throws InvalidInputException
	 */
	public static Namespace getNamespaceFromName(String name) throws DuplicateNameException, InvalidInputException {
		Namespace ns = utilsCtx.api.getNamespace(null, name);
		if (ns == null) { //Create namespace
			ns = utilsCtx.program.getSymbolTable().createNameSpace(null, name, SourceType.ANALYSIS);
		}

		return ns;
	}
	
	public static void createDataInNamespace(Address address, Namespace ns, String name, DataType type) throws Exception {
		if (!type.isZeroLength() && type.getLength() > 0) {
			utilsCtx.api.clearListing(address, address.add(type.getLength() - 1));
		}
		try {
			utilsCtx.api.createData(address, type);
		} catch (CodeUnitInsertionException e) {
			if (!type.isZeroLength() && type.getLength() > 0) {
				utilsCtx.logger.appendMsg("Exception when creating datatype " + type.getName() + " @ " + address.toString());
				utilsCtx.logger.appendException(e);
			} else {
				//Everything is fine.
			}
		}
		utilsCtx.api.createLabel(address, name, ns, true, SourceType.ANALYSIS);
		
	}
	
	public static void createDataInNamespace(Address address, String namespaceName, String name, DataType type) throws Exception {
		createDataInNamespace(address, getNamespaceFromName(namespaceName), name, type);
	}
	
	public static Symbol createLabel(Address address, String label, boolean isPrimary) throws Exception {
		return utilsCtx.api.createLabel(address, label, isPrimary, SourceType.ANALYSIS);
	}
	
	public static Symbol getSymbolAt(Address address) {
		return utilsCtx.api.getSymbolAt(address);
	}
	
	public static String getPlateCommentAt(Address address) {
		return utilsCtx.api.getPlateComment(address);
	}
	
	public static void appendLogMsg(String message) {
		utilsCtx.logger.appendMsg(message);
	}
	
	public static BinaryReader getMemoryReader(Address addr) {
		return new BinaryReader(new MemoryByteProvider(utilsCtx.memory, addr), /* Little-endian */true);
	}
	
	public static long getModuleSDKVersion() {
		return utilsCtx.SDKVersion;
	}
	
	public static void setModuleSDKVersion(long version) {
		utilsCtx.SDKVersion = version;
	}
	
	public static void setMonitorMessage(TaskMonitor monitor, String msg) {
		monitor.setShowProgressValue(false);
		monitor.setMessage(msg);
	}
	
	public static void prepareMonitorProgressBar(TaskMonitor monitor, String msg, long max) {
		monitor.setShowProgressValue(false);
		monitor.setMessage(msg);
		monitor.setMaximum(max);
		monitor.setShowProgressValue(true);
	}
	
	public static void setPlateComment(Address addr, String comment) {
		utilsCtx.api.setPlateComment(addr, comment);
	}
	
	public static ExternalLocation addExternalFunction(String libraryName, String extLabel) throws InvalidInputException, DuplicateNameException {
		if (extLabel == null) {
			throw new RuntimeException("NULL extLabel!");
		}
		
		if (libraryName == null) { //Create in "EXTERNAL" pseudolibrary
			return utilsCtx.program.getExternalManager().addExtFunction((Namespace)null, extLabel, null, SourceType.ANALYSIS);
		}
		return utilsCtx.program.getExternalManager().addExtFunction(libraryName, extLabel, null, SourceType.ANALYSIS);
	}
	
	//TODO make public?
	private static Function _createFunction(String name, long rawAddress, boolean makeFallbackLabelPrimary, boolean makeFunctionEntrypoint) throws Exception {
		boolean isThumb = (rawAddress & 1L) != 0;
		rawAddress &= ~1L; //Clear Thumb bit	
		
		Address funcEntry = Utils.getProgramAddress(rawAddress);
		Function func = utilsCtx.api.getFunctionAt(funcEntry);
		if (func != null) { //Already exists - just markup TMode, add secondary label and return the function
			utilsCtx.api.createLabel(funcEntry, name, makeFallbackLabelPrimary, SourceType.ANALYSIS);
		} else {
			func = utilsCtx.helper.createOneByteFunction(name, funcEntry, makeFunctionEntrypoint);
			func.setSignatureSource(SourceType.ANALYSIS);
		}
		markupTMode(funcEntry, isThumb);
		return func;
	}
	
	/**
	 * Creates an entrypoint function at a given address if it doesn't exist, else returns the existing function.
	 * If the function already exists, the name is added as a primary/secondary label instead, and isEntrypoint is ignored.
	 * TMode is always marked up based on the provided address.
	 * @param name  Name of the function
	 * @param address  Address of the function
	 * @param isPrimary Should the label be primary if funciton already exists?
	 * @return The created/existing function
	 * @throws Exception 
	 */
	public static Function createEntrypointFunction(String name, long address, boolean isPrimary) throws Exception {
		return _createFunction(name, address, isPrimary, true);
	}
	
	/**
	 * Creates a function at a given address if it doesn't exist, else returns the existing function.
	 * If the function already exists, the name is added as a secondary label instead, and isEntrypoint is ignored.
	 * TMode is always marked up based on the provided address.
	 * @param name  Name of the function
	 * @param address  Address of the function
	 * @param isEntrypoint  Is the function an entrypoint?
	 * @return The created/existing function
	 * @throws Exception 
	 */
	public static Function createFunction(String name, long address) throws Exception {
		return _createFunction(name, address, false, false);
	}
	
	public static void setProgramInformation(String name, String value) {
		Options programInfos = utilsCtx.program.getOptions(Program.PROGRAM_INFO);
		programInfos.setString(name, value);
	}
	
	public static void markupTMode(long address) throws ContextChangeException, AddressOutOfBoundsException {
		boolean isThumb = (address & 1L) != 0;
		address = (address & ~1L); //Clear Thumb bit
		
		markupTMode(Utils.getProgramAddress(address), isThumb);
	}
	
	
	/* Private utility functions */
	private static void markupTMode(Address ep, boolean isThumb) throws ContextChangeException, AddressOutOfBoundsException {
		//Markup TMode to give disassembly hint - now analysis will not break anymore!
		if (isThumb) {
			utilsCtx.progContext.setRegisterValue(ep, ep.add(2), ThumbTMode);
		} else {
			utilsCtx.progContext.setRegisterValue(ep, ep.add(4), ARMTMode);
		}
	}
}
