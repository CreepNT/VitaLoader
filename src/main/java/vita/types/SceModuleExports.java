package vita.types;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.util.Map;


import ghidra.util.task.TaskMonitor;
import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.util.exception.DuplicateNameException;

import vita.misc.TypeHelper;
import vita.elf.VitaElfExtension.ProcessingContext;

public class SceModuleExports implements StructConverter {
	public int size;
	public int version;
	public int attributes;
	public int num_functions;
	public int num_vars;
	public int num_tls_vars;
	public int unknown1;
	public long library_nid;
	public long library_name_ptr;
	public long nid_table;		//Contains the function NIDs followed by the variable NIDs
	public long entry_table;	//Contains the function entrypoints followed by pointers(?) to variables
	public static final int SIZE = 0x20;
	public static final String NAME = "SceModuleExports";
	
	private static final String MODULE_START_FUNC_NAME 	= "module_start";
	private static final String MODULE_STOP_FUNC_NAME 	= "module_stop";
	private static final String MODULE_EXIT_FUNC_NAME 	= "module_exit";
	private static final String MODULE_BOOTSTART_FUNC_NAME = "module_bootstart";
	private static final Map<Integer, String> NAMELESS_FUNC_EXPORTS = Map.of(
			0x935CD196, MODULE_START_FUNC_NAME,
			0x79F8E492, MODULE_STOP_FUNC_NAME,
			0x913482A9, MODULE_EXIT_FUNC_NAME,
			0x5C424D40, MODULE_BOOTSTART_FUNC_NAME
	);
	
	private static final long MODULE_INFO_NID 			= 0x6C2224BAL; //SceModuleInfo
	private static final String MODULE_SDK_VERSION_VARIABLE_NAME = "__crt0_main_sdk_version_var";
	private static final long MODULE_SDK_VERSION_NID 	= 0x936C8A78L; //SceUInt32
	
	private static final long PROCESS_PARAM_NID 		= 0x70FBA1E7L; //SceProcessParam
	
	private static final long STATIC_PROBES_INFO_NID = 0x9318D9DDL;
	private static final long STATIC_PROBES_ARRAY_NID = 0x8CE938B1L;
	
	private ProcessingContext _ctx; //Processing context
	private Address _selfAddress; 	//Address we're located at
	private String _libraryName; 	//Name of the library those exports belong to
	
	private int numStaticProbes = 0; //Number of entries in the static probes array
	private Address staticProbesAddr = null; //address of the array
	
	
	private Namespace _libraryNS;
	
	/**
	 * 
	 * @param ctx ELF processing context
	 * @param moduleExportsAddr Address this structure is located at 
	 * @param moduleName Name of the currently processed module
	 * @throws IOException
	 */
	public SceModuleExports(ProcessingContext ctx, Address moduleExportsAddr) 
			throws Exception {
		BinaryReader reader = TypeHelper.getByteArrayBackedBinaryReader(ctx, moduleExportsAddr, SIZE);
		
		size 			= reader.readNextUnsignedShort();
		version 		= reader.readNextUnsignedShort();
		attributes 		= reader.readNextUnsignedShort();
		num_functions 	= reader.readNextUnsignedShort();
		num_vars 		= reader.readNextUnsignedShort();
		num_tls_vars 	= reader.readNextUnsignedShort();
		unknown1 		= reader.readNextInt();
		library_nid 	= reader.readNextUnsignedInt();
		library_name_ptr = reader.readNextUnsignedInt();
		nid_table 		= reader.readNextUnsignedInt();
		entry_table 	= reader.readNextUnsignedInt();
		
		_ctx = ctx;
		_selfAddress = moduleExportsAddr;
		_libraryName = null;
		
		//Parse library name if present
		if (this.library_name_ptr != 0L) {
			Address libNameAddress = _ctx.textBlock.getStart().getNewAddress(this.library_name_ptr);
			Data libNameString = _ctx.api.createAsciiString(libNameAddress);
			byte[] stringBytes = libNameString.getBytes();
			
			_libraryName = new String(stringBytes, 0, stringBytes.length - 1); //Remove NUL
			
			if (isNONAMELibrary()) {
				_ctx.logger.appendMsg(String.format("WARNING: NONAME library has a name! (name=%s)", _libraryName));
			}
			
			//BinaryReader libNameReader = TypeHelper.getMemoryBackedBinaryReader(ctx.memory,
			//		ctx.textBlock.getStart().getNewAddress(this.library_name_ptr));
			//_libraryName = libNameReader.readNextAsciiString();
		} else if (!isNONAMELibrary()) {
			_ctx.logger.appendMsg(String.format("WARNING: Unnamed library found (NID = 0x%08X)", library_nid));
			_libraryName = String.format("UNNAMED_%08X", library_nid);
		} else {
			_libraryName = "NONAME";
		}
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}
	
	/**
	 * Applies the structure in the program listing
	 * @throws Exception
	 */
	public void apply() throws Exception {
		//Create structure object
		StructureDataType dt = TypeHelper.createAndGetStructureDataType(NAME);
		dt.add(WORD, "size", "Size of this structure");
		dt.add(WORD, "version", null);
		dt.add(WORD, "attributes", null);
		dt.add(WORD, "numFunctions", "Number of functions exported by this library");
		dt.add(WORD, "numVars", "Number of variables exported by this library");
		dt.add(WORD, "numTLSVars", "Number of TLS variables variables exported by this library? (maybe wrong)");
		dt.add(DWORD, "unk18", null);
		dt.add(DWORD, "libraryNID", "Numeric ID of library");
		dt.add(Pointer32DataType.dataType, "libraryName", "Pointer to library name"); //TODO: make this char*
		dt.add(Pointer32DataType.dataType, "pNIDTable", "Pointer to the table of all NIDs exported by this library"); //TODO: make this SceUInt32*
		dt.add(Pointer32DataType.dataType, "pEntryTable", "Pointer to the table of all functions/variables exported by this library"); //TODO: make this void**
		
		if (dt.getLength() != SIZE)
			System.err.println("Unexpected " + NAME + " data type size (" + dt.getLength() + " != expected " + SIZE + " !)");

		//Cleanup area then apply structure
		_ctx.api.clearListing(_selfAddress, _selfAddress.add(dt.getLength()));
		_ctx.api.createData(_selfAddress, dt);
		
		//Create library namespace and markup structure
		if (isNONAMELibrary()) {
			_libraryNS = _ctx.program.getGlobalNamespace();
			_ctx.api.createLabel(_selfAddress, "NONAME_SceModuleExports", true, SourceType.ANALYSIS);
		} else {
			_libraryNS = _ctx.program.getSymbolTable().createNameSpace(null, _libraryName, SourceType.ANALYSIS);
			_ctx.api.createLabel(_selfAddress, NAME, _libraryNS, true, SourceType.ANALYSIS);
		}
	}
	
	/**
	 * Processes the structure's content
	 */
	public void process() throws Exception {
		//Create NID and entry tables
		Address nidTableAddress = _ctx.textBlock.getStart().getNewAddress(nid_table);
		Address entryTableAddress = _ctx.textBlock.getStart().getNewAddress(entry_table);

		_ctx.helper.createData(nidTableAddress, TypeHelper.makeArray(TypeHelper.u32, (num_functions + num_vars)));
		_ctx.helper.createData(entryTableAddress, TypeHelper.makeArray(Pointer32DataType.dataType, (num_functions + num_vars)));
		_ctx.api.createLabel(entryTableAddress, "EntryTable", _libraryNS, true, SourceType.ANALYSIS);
		_ctx.api.createLabel(nidTableAddress, "NIDTable", _libraryNS, true, SourceType.ANALYSIS);
		
		
		//Process exported functions
		if (num_functions > 0) {
			byte[] funcNidTableBytes = new byte[4 * num_functions];
			byte[] funcEntryTableBytes = new byte[4 * num_functions];
			_ctx.textBlock.getBytes(nidTableAddress, funcNidTableBytes);
			_ctx.textBlock.getBytes(entryTableAddress, funcEntryTableBytes);
			
			IntBuffer funcNidTable = ByteBuffer.wrap(funcNidTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
			IntBuffer funcEntryTable = ByteBuffer.wrap(funcEntryTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
			
			prepareMonitorProgressBar(_ctx.monitor, "Processing function exports from " + _libraryName + "...", num_functions);
			for (int i = 0; i < num_functions; i++, _ctx.monitor.incrementProgress(1)) {
				processFunction(Integer.toUnsignedLong(funcNidTable.get(i)), Integer.toUnsignedLong(funcEntryTable.get(i)));
			}
		}
				
		//Process exported variables
		if (num_vars > 0) {
			byte[] varNidTableBytes = new byte[4 * num_vars];
			byte[] varEntryTableBytes = new byte[4 * num_vars];
			
			//Skip the part covered by functions
			_ctx.textBlock.getBytes(nidTableAddress.add(4 * num_functions), varNidTableBytes);
			_ctx.textBlock.getBytes(entryTableAddress.add(4 * num_functions), varEntryTableBytes);
			
			IntBuffer varNidTable = ByteBuffer.wrap(varNidTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
			IntBuffer varEntryTable = ByteBuffer.wrap(varEntryTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
		
			prepareMonitorProgressBar(_ctx.monitor, "Processing variable exports from " + _libraryName + "...", num_vars);
			for (int i = 0; i < num_vars; i++, _ctx.monitor.incrementProgress(1)) {
				processVariable(Integer.toUnsignedLong(varNidTable.get(i)), Integer.toUnsignedLong(varEntryTable.get(i)));
			}
			
			//Process static probes
			processStaticProbes();
		}
		_ctx.monitor.setShowProgressValue(false);
	}
	
	//Private routines used for processing
	private void processFunction(long functionNid, long functionEntry) throws Exception {
		boolean isThumb = (functionEntry & 1L) != 0;
		functionEntry = functionEntry & ~1L; //Clear LSB, because functions have to start at a 2-byte boundary (i.e. ignore Thumb bit)
		
		String funcName;
		String funcComment;
		Address funcAddr = _ctx.textBlock.getStart().getNewAddress(functionEntry);
		
		if (isNONAMELibrary()) {
			if (NAMELESS_FUNC_EXPORTS.containsKey((int)functionNid)) {
				funcName = NAMELESS_FUNC_EXPORTS.get((int)functionNid);
			}
			else {
				_ctx.logger.appendMsg(String.format("!!!Unknown NONAME function with NID 0x%08X", functionNid));
				funcName = String.format("NONAME_%08X", functionNid);
			}
			funcComment = String.format("NONAME export: %s", funcName);
		} else {
			funcName = _ctx.nidDb.getFunctionName(this.library_nid, functionNid);
			if (funcName == null) { //Not found in database
				funcName = _libraryName + String.format("_%08X", functionNid);
			}
			funcComment = String.format("Exporting library : %s (NID 0x%08X)\nFunction NID : 0x%08X\n---   %s_0x%08X   ---", _libraryName, this.library_nid, functionNid, _libraryName, functionNid);
		}
		
		//See if a function already exists
		Function func = _ctx.api.getFunctionAt(funcAddr);
		if (func == null) { //No - create one
			func = _ctx.helper.createOneByteFunction(funcName, funcAddr, true);
			func.setSignatureSource(SourceType.ANALYSIS);
		} else { //Function already exists - probably export aliases
			//Simply add a label and apppend to comment
			_ctx.api.createLabel(funcAddr, funcName, false, SourceType.ANALYSIS);
			funcComment = func.getComment() + funcComment;
		}
		
		func.setComment(funcComment);
		
		//Markup TMode to give disassembly hint - now analysis will not break anymore!
		if (isThumb) {
			_ctx.progContext.setRegisterValue(funcAddr, funcAddr.add(2), _ctx.TModeForThumb);
		} else {
			_ctx.progContext.setRegisterValue(funcAddr, funcAddr.add(4), _ctx.TModeForARM);
		}
		
		//Mark as exported
		//TODO, if possible: sort functions based on library name
		//_ctx.program.getSymbolTable().addExternalEntryPoint(functionEntryAddr); //is this needed anymore?
	}

	private void processVariable(long varNID, long rawVarAddress) throws Exception {
		Address varAddr = _ctx.textStart.getNewAddress(rawVarAddress);
		if (!isNONAMELibrary()) {
			String varName = _ctx.nidDb.getVariableName(this.library_nid, varNID);
			if (varName == null) {
				varName = String.format("%s_%08X", _libraryName, varNID);
			}
			
			_ctx.api.createLabel(varAddr, varName, _libraryNS, true, SourceType.ANALYSIS);
		} else {
			if (varNID == MODULE_INFO_NID) { //Parsing of ELFs begins by finding and parsing the SceModuleInfo, so nothing to do
				return;
			} else if (varNID == MODULE_SDK_VERSION_NID) {
				_ctx.api.createData(varAddr, UnsignedIntegerDataType.dataType); //TODO SceUInt32
				_ctx.api.createLabel(varAddr, MODULE_SDK_VERSION_VARIABLE_NAME, true, SourceType.ANALYSIS);
			} else if (varNID == PROCESS_PARAM_NID) {
				new SceProcessParam(_ctx, varAddr).apply();
			} else if (varNID == STATIC_PROBES_INFO_NID) {
			    _ctx.api.createData(varAddr, TypeHelper.makeArray(TypeHelper.u32, 2));
				_ctx.api.createLabel(varAddr, "static_probes_info", true, SourceType.ANALYSIS);
				
				BinaryReader br = TypeHelper.getByteArrayBackedBinaryReader(_ctx, varAddr, 0x8);
				long piVersion = br.readNextUnsignedInt();
				if (piVersion != 1L) {
					_ctx.logger.appendMsg(String.format("WARNING: static probes info version mismatch! (%d != %d)", piVersion, 1));
					return;
				}
				numStaticProbes = (int)br.readNextUnsignedInt();
			} else if (varNID == STATIC_PROBES_ARRAY_NID) {
				staticProbesAddr = varAddr;
			} else {
				_ctx.logger.appendMsg(String.format("!!!Unknown NONAME variable with NID 0x%08X", varNID));
			}
		}
	}
	
/*
 * Gadgets
 */
	private void processStaticProbes() throws Exception {
		if (numStaticProbes == 0 && staticProbesAddr == null) { //No static probes - everything is fine
			return;
		}
		
		if (numStaticProbes != 0 && staticProbesAddr == null) {
			_ctx.logger.appendMsg("WARNING: module exports static probes info, but no static probes!");
			return;
		}
		
		if (numStaticProbes == 0 && staticProbesAddr != null) {
			_ctx.logger.appendMsg("WARNING: module exports static probes, but no static probes info!");
			return;
		}
		
		_ctx.api.createData(staticProbesAddr, TypeHelper.makeArray(new Pointer32DataType(SceModuleStaticProbe.getDataType()), numStaticProbes));
		_ctx.api.createLabel(staticProbesAddr, "static_probes", true, SourceType.ANALYSIS);
		
		
		BinaryReader probesArrayReader = TypeHelper.getByteArrayBackedBinaryReader(_ctx, staticProbesAddr, numStaticProbes * 4 + 4); //+4 for the last (NULL) entry
		int numProbesCounted = 0;
		for (int i = 0; i <= numStaticProbes; i++) {
			long ptr = probesArrayReader.readNextInt();
			if (ptr != 0L) {
				numProbesCounted += 1;
			} else {
				break;
			}
		}
		
		//Verify that size matches info.size
		if (numProbesCounted != numStaticProbes) {
			_ctx.logger.appendMsg(String.format("WARNING: mismatched static probes count (info->%d != %d)", numStaticProbes, numProbesCounted));
			return;
		}
		
		probesArrayReader.setPointerIndex(0);
		for (int i = 0; i < numStaticProbes; i++) {
			long ptr = probesArrayReader.readNextUnsignedInt();
			Address probeAddr = _ctx.textStart.getNewAddress(ptr);
			SceModuleStaticProbe probe = new SceModuleStaticProbe(_ctx, probeAddr);
			probe.apply();
			probe.process();
		}
		
		_ctx.logger.appendMsg(String.format("Module exports %d static probes.", numStaticProbes));
		
	}
	
	private static void prepareMonitorProgressBar(TaskMonitor monitor, String msg, long max) {
		monitor.setShowProgressValue(false);
		monitor.setMessage(msg);
		monitor.setMaximum(max);
		monitor.setShowProgressValue(true);
	}
	
	private boolean isNONAMELibrary() {
		return ((attributes & 0x8000) != 0);
	}
}
