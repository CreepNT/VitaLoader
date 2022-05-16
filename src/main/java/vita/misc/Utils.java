package vita.misc;

import java.math.BigInteger;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
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
	
	public static long getModuleSDKVersion() {
		return utilsCtx.SDKVersion;
	}
	
	public static void setModuleSDKVersion(long version) {
		utilsCtx.SDKVersion = version;
	}
	
	public static void prepareMonitorProgressBar(TaskMonitor monitor, String msg, long max) {
		monitor.setShowProgressValue(false);
		monitor.setMessage(msg);
		monitor.setMaximum(max);
		monitor.setShowProgressValue(true);
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
	public static Function createFunction(String name, long address, boolean isEntrypoint) throws Exception {
		boolean isThumb = (address & 1L) != 0;
		address = (address & ~1L); //Clear Thumb bit	
		
		Address funcEntry = utilsCtx.textStart.getNewAddress(address);
		Function func = utilsCtx.api.getFunctionAt(funcEntry);
		if (func != null) { //Already exists - just markup TMode, add secondary label and return the function
			utilsCtx.api.createLabel(funcEntry, name, false, SourceType.ANALYSIS);
			markupTMode(funcEntry, isThumb);
			return func;
		}
		
		func = utilsCtx.helper.createOneByteFunction(name, funcEntry, isEntrypoint);
		func.setSignatureSource(SourceType.ANALYSIS);
		markupTMode(funcEntry, isThumb);
		return func;
	}
	
	public static void markupTMode(long address) throws ContextChangeException, AddressOutOfBoundsException {
		boolean isThumb = (address & 1L) != 0;
		address = (address & ~1L); //Clear Thumb bit
		
		markupTMode(utilsCtx.textStart.getNewAddress(address), isThumb);
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
