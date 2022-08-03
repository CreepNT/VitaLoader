package vita.types;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.util.Map;


import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.Pointer32DataType;

import vita.misc.TypeManager;
import vita.misc.Utils;
import vita.types.SceModuleThreadParameter.ModuleThreadParameterType;
import vita.elf.VitaElfExtension.ProcessingContext;

public class SceLibEntryTable {
	public static final String STRUCTURE_NAME = SceLibEntryTable.class.getSimpleName();
	
	public short size;
	public short auxattribute;
	public int version;
	public int attributes;
	public int numFuncs;
	public int numVars;
	public int numTLSVars;
	public short hashinfo;
	public short hashinfotls;
	public short reserved0xD;
	public short nidaltsets;
	public long libraryNID; //Not present in 0x1C
	public long pLibName;
	//Tables are organized as follow: first functions, then variables, then TLS variables.
	//On 0.931, library NID is 8 bytes before the library name.
	public long pNidTbl;
	public long pEntryTbl;
	public long _sce_package_version;

	private final ProcessingContext _ctx; 	//Processing context
	private final Address _selfAddress; 	//Address this structure is located at
	
	private final String _libName; 		//Name of this library
	private Namespace _libNamespace; 	//Namespace used to store library objects
	
	
	private int _numStaticProbes = 0; 			//Number of entries in the static probes array
	private Address _staticProbesAddr = null; 	//Address of the array
	private final int _numExports;			    //Total number of exports
	
	//Structure datatype of this instance
	private StructureDataType DATATYPE = null;
	
	private static final Map<Integer, String> NAMELESS_FUNC_EXPORTS = Map.of(
			0x935CD196, "module_start",
			0x79F8E492, "module_stop",
			0x913482A9, "module_exit",
			0x5C424D40, "module_bootstart",
			0xE640E30C, "module_proc_create",
			0x4F0EE5BD, "module_proc_exit",
			0xDF0212B9, "module_proc_kill",
			0xDD42FA37, "module_suspend"
	);
	
	private static final long MODULE_SDK_VERSION_NID 	= 0x936C8A78L; //SceUInt32 module_sdk_version
	private static final long MODULE_INFO_NID 			= 0x6C2224BAL; //SceModuleInfo module_info
	
	private static final long PROCESS_PARAM_NID 		= 0x70FBA1E7L; //SceProcessParam module_proc_param
	
	private static final long MODULE_DTRACE_PROBES_NID = 0x8CE938B1L; //sdt_probedesc_t module_dtrace_probes
	private static final long MODULE_DTRACE_PROBES_INFO_NID = 0x9318D9DDL; //sdt_probes_info_t module_dtrace_probes_info
	
	
	//SceModuleThreadParameter
	private static final long MODULE_START_THREAD_PARAMETER_NID = 0x1A9822A4L; //sce_module_start_thread_parameter
	private static final long MODULE_STOP_THREAD_PARAMETER_NID = 0xD20886EBL;  //sce_module_stop_thread_parameter
	/**
	 * Creates an instance of the SceModuleExports structure object, and creates the structure in the listing at provided address
	 * @param ctx ELF processing context
	 * @param moduleExportsAddr Address this structure is located at 
	 * @param moduleName Name of the currently processed module
	 * @throws IOException
	 */
	public SceLibEntryTable(ProcessingContext ctx, Address moduleExportsAddr) 
			throws Exception {
		_ctx = ctx;
		_selfAddress = moduleExportsAddr;
		
		BinaryReader reader = Utils.getMemoryReader(_selfAddress);
		
		size 			= reader.readNextByte();
		auxattribute    = reader.readNextByte();
		version 		= reader.readNextUnsignedShort();
		attributes 		= reader.readNextUnsignedShort();
		numFuncs 		= reader.readNextUnsignedShort();
		numVars 		= reader.readNextUnsignedShort();
		numTLSVars 		= reader.readNextUnsignedShort();
		hashinfo 		= reader.readNextByte();
		hashinfotls 	= reader.readNextByte();
		reserved0xD		= reader.readNextByte();
		nidaltsets		= reader.readNextByte();
		
		if (size == 0x20) {
			libraryNID = reader.readNextUnsignedInt();
			pLibName = reader.readNextUnsignedInt();
		} else if (size == 0x1C) {
			pLibName = reader.readNextUnsignedInt();
			if (pLibName == 0L) {
				libraryNID = 0L; //NONAME library
			}
		} else {
			throw new RuntimeException(String.format("Unknown SceModuleExports with size 0x%08X!", size));
		}
		
		pNidTbl 	= reader.readNextUnsignedInt();
		pEntryTbl 	= reader.readNextUnsignedInt();

		_numExports = numFuncs + numVars + numTLSVars;
		
		//Parse library name if present
		if (this.pLibName != 0L) {
			if (size == 0x1C) {
				Address libMetadataReader = Utils.getProgramAddress(pLibName - 8);
				BinaryReader metadataReader = Utils.getMemoryReader(libMetadataReader);
				libraryNID = metadataReader.readNextUnsignedInt();
				_sce_package_version = metadataReader.readNextUnsignedInt();
				_libName = metadataReader.readNextAsciiString();
				_libNamespace = Utils.getNamespaceFromName(_libName);
				
				Utils.createDataInNamespace(libMetadataReader, _libNamespace, "_" + _libName + "_nid", TypeManager.u32);
				Utils.createDataInNamespace(libMetadataReader.add(4), _libNamespace, "_sce_package_version_" + _libName, TypeManager.u32);
				Utils.createDataInNamespace(libMetadataReader.add(8), _libNamespace, "_" + _libName + "_stub_str", new TerminatedStringDataType());
			} else {
				Address libNameAddress = Utils.getProgramAddress(this.pLibName);
				BinaryReader libNameReader = Utils.getMemoryReader(libNameAddress);
				_libName = libNameReader.readNextAsciiString();
				_libNamespace = Utils.getNamespaceFromName(_libName);
				
				Utils.createDataInNamespace(libNameAddress, _libNamespace, "_" + _libName + "_str", new TerminatedStringDataType());
			}
			
			if (isNONAMELibrary()) {
				Utils.appendLogMsg(String.format("WARNING: NONAME library has a name! (name=%s)", _libName));
			}
		} else if (!isNONAMELibrary()) {
			Utils.appendLogMsg(String.format("WARNING: Unnamed library found (NID = 0x%08X)", libraryNID));
			_libName = String.format("UNNAMED_%08X", libraryNID);
			_libNamespace = Utils.getNamespaceFromName(_libName);
		} else {
			_libName = "NONAME";
			_libNamespace = Utils.getModuleNamespace();
		}

		Utils.createDataInNamespace(_selfAddress, _libNamespace, STRUCTURE_NAME, this.toDataType());
	}

	
	public DataType toDataType() {
		if (DATATYPE == null) {
			final DataType SceUInt8  = TypeManager.getDataType("SceUInt8");
			final DataType SceUInt16 = TypeManager.getDataType("SceUInt16");
			final DataType SceUInt32 = TypeManager.getDataType("SceUInt32");
			final DataType LIBRARY_ATTRIBUTES = TypeManager.getDataType("LIBRARY_ATTRIBUTES");
			
			DATATYPE = new StructureDataType(TypeManager.SCE_TYPES_CATPATH, STRUCTURE_NAME + String.format("_0x%X", size), 0);
			DATATYPE.add(SceUInt8,  "size", "Size of this structure");
			DATATYPE.add(SceUInt8,  "auxattribute", null);
			DATATYPE.add(SceUInt16, "version", "Library version?");
			DATATYPE.add(LIBRARY_ATTRIBUTES, "attributes", "Library attributes");
			DATATYPE.add(SceUInt16, "numFuncs", "Number of functions exported by this library");
			DATATYPE.add(SceUInt16, "numVars", "Number of variables exported by this library");
			DATATYPE.add(SceUInt16, "numTLSVars", "Number of TLS variables variables exported by this library");
			DATATYPE.add(SceUInt8,  "hashInfo", "Hash info of (numFuncs + numVars << 4)");
			DATATYPE.add(SceUInt8,  "hashInfoTLS", "Hash info of numTLSVars");
			DATATYPE.add(SceUInt8,  "reserved0xD", "Reserved?");
			DATATYPE.add(SceUInt8,  "nidaltsets", null);
			
			if (size == 0x20) {
				DATATYPE.add(SceUInt32, "libraryNID", "Numeric ID of library");
			}
			
			DATATYPE.add(new Pointer32DataType(CharDataType.dataType), "libraryName", "Pointer to library name");
			DATATYPE.add(new Pointer32DataType(TypeManager.getDataType("SceUInt32")), "pNIDTable", "Pointer to the table of all NIDs exported by this library");
			DATATYPE.add(new Pointer32DataType(Pointer32DataType.dataType), "pEntryTable", "Pointer to the table of all functions/variables exported by this library");
		}
		
		return DATATYPE;
	}
	
	/**
	 * Processes the structure's content
	 */
	public void process() throws Exception {
		//Create NID and entry tables
		Address nidTableAddress = Utils.getProgramAddress(pNidTbl);
		Address entryTableAddress = Utils.getProgramAddress(pEntryTbl);
		
		//TODO: is this correct?
		Utils.createDataInNamespace(entryTableAddress, _libNamespace, "_" + _libName + "entry_table", Utils.makeArray(Pointer32DataType.dataType, _numExports));
		Utils.createDataInNamespace(nidTableAddress, _libNamespace, "_" + _libName + "nid_table", Utils.makeArray(TypeManager.getDataType("SceUInt32"), _numExports));
		
		//Process exported functions
		if (numFuncs > 0) {
			Utils.prepareMonitorProgressBar(_ctx.monitor, "Processing function exports from " + _libName + "...", numFuncs);
			
			byte[] funcNidTableBytes = new byte[4 * numFuncs];
			byte[] funcEntryTableBytes = new byte[4 * numFuncs];
			
			Utils.getBytes(nidTableAddress, funcNidTableBytes);
			Utils.getBytes(entryTableAddress, funcEntryTableBytes);
			
			IntBuffer funcNidTable = ByteBuffer.wrap(funcNidTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
			IntBuffer funcEntryTable = ByteBuffer.wrap(funcEntryTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
			
			for (int i = 0; i < numFuncs; i++, _ctx.monitor.incrementProgress(1)) {
				processFunction(Integer.toUnsignedLong(funcNidTable.get(i)), Integer.toUnsignedLong(funcEntryTable.get(i)));
			}
		}
				
		//Process exported variables
		if (numVars > 0) {
			Utils.prepareMonitorProgressBar(_ctx.monitor, "Processing variable exports from " + _libName + "...", numVars);
			
			byte[] varNidTableBytes = new byte[4 * numVars];
			byte[] varEntryTableBytes = new byte[4 * numVars];
			
			int offset = 4 * numFuncs;
			
			//Read past the space for functions
			Utils.getBytes(nidTableAddress.add(offset), varNidTableBytes);
			Utils.getBytes(entryTableAddress.add(offset), varEntryTableBytes);
			
			IntBuffer varNidTable = ByteBuffer.wrap(varNidTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
			IntBuffer varEntryTable = ByteBuffer.wrap(varEntryTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
		
			for (int i = 0; i < numVars; i++, _ctx.monitor.incrementProgress(1)) {
				processVariable(Integer.toUnsignedLong(varNidTable.get(i)), Integer.toUnsignedLong(varEntryTable.get(i)), false);
			}
			
			//Process static probes
			processStaticProbes();
		}
		
		//Process TLS variables
		if (numTLSVars > 0)  {
			Utils.prepareMonitorProgressBar(_ctx.monitor, "Processing TLS variable exports from " + _libName + "...", numTLSVars);
			
			byte[] TLSVarNidTableBytes = new byte[4 * numTLSVars];
			byte[] TLSVarEntryTableBytes = new byte[4 * numTLSVars];
			
			int offset = 4 * numFuncs + 4 * numVars;
			
			//Read past the space for functions and variables
			Utils.getBytes(nidTableAddress.add(offset), TLSVarNidTableBytes);
			Utils.getBytes(entryTableAddress.add(offset), TLSVarEntryTableBytes);
			
			IntBuffer TLSVarNidTable = ByteBuffer.wrap(TLSVarNidTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
			IntBuffer TLSVarEntryTable = ByteBuffer.wrap(TLSVarEntryTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
			
			for (int i = 0; i < numTLSVars; i++, _ctx.monitor.incrementProgress(1)) {
				processVariable(Integer.toUnsignedLong(TLSVarNidTable.get(i)), Integer.toUnsignedLong(TLSVarEntryTable.get(i)), true);
			}
		}
		
		_ctx.monitor.setShowProgressValue(false);
	}
	
	//Private routines used for processing
	private void processFunction(long functionNid, long functionEntry) throws Exception {
		//HACK: in 0.931, some modules have static probes exported as functions
		//Redirect to variable if detected
		if (isNONAMELibrary() && (functionNid == MODULE_DTRACE_PROBES_INFO_NID || functionNid == MODULE_DTRACE_PROBES_NID)) {
			processVariable(functionNid, functionEntry, false);
			return;
		}
		
		String defaultName = String.format("%s_%08X", _libName, functionNid);
		String funcComment = makeFunctionPlateComment(functionNid);
		String readableFuncName = null; //Human-readable (non-default) function name
		Address funcAddr = Utils.getProgramAddress(functionEntry & ~1L); //Functions always start at a 2-byte aligned address
		
		if (!isNONAMELibrary()) {
			readableFuncName = _ctx.nidDb.getFunctionName(_libName, libraryNID, functionNid);
		} else {
			if (NAMELESS_FUNC_EXPORTS.containsKey((int)functionNid)) {
				//Overwrite defautName instead of using readableFuncName to avoid needed special code
				//to not have the default name show up for NONAME exports.
				defaultName = NAMELESS_FUNC_EXPORTS.get((int)functionNid);
			}
			else {
				_ctx.logger.appendMsg(String.format("Module exports unknown NONAME function with NID 0x%08X.", functionNid));
			}
		}
		
		final boolean functionExists = (_ctx.api.getFunctionAt(funcAddr) != null);
		final boolean hasReadableName = (readableFuncName != null);

		//Create the function if it didn't exist, markup TMode and add default name label otherwise.
		//We can only use default names as primary if we are creating the function and there is no database name.
		Function func = Utils.createEntrypointFunction(defaultName, functionEntry, (!hasReadableName && !functionExists));

		String previousComment = func.getComment();
		if (previousComment != null) {
			funcComment = previousComment + "\n\n" + funcComment;
		}
		
		if (hasReadableName) {
			// When an unknown export aliases a known (i.e. with an entry in NID database) export, depending on the processing order,
			// it is possible for the function export to have a default name as its primary export. If we don't create this label as primary,
			// this ends up with the function's name (i.e. primary label) being a default name, even though the NID database has the function's name!
			//
			// Avoid this problem by always treating database names as primary labels. If two aliases have the same name in database, it seems that
			// Ghidra silently eats the second label creation and only one remain, which is exactly what we want.
			Utils.createEntrypointFunction(readableFuncName, functionEntry, true);
		}
		
		if (!isNONAMELibrary()) { //Don't add comment to NONAME functions
			func.setComment(funcComment);
		}
		
		//It doesn't seem possible to sort exported functions based on library name (without using namespaces, which defeats the purpose), so leave as-is
	}

	private void processVariable(long varNID, long rawVarAddress, boolean isTLS) throws Exception {
		Address varAddr = Utils.getProgramAddressUnchecked(rawVarAddress);
		if (varAddr == null) {
			//Certain modules (e.g. SceKernelPsp2Config) export variables that point outside of the module.
			//Attempting to markup those variables will result is irrelevant in catastrophic failures, so skip them.
			return;
		}
		
		if (isNONAMELibrary()) {
			if (!isTLS) {
				processNONAMEVariable(varNID, varAddr);	
			} else {
				_ctx.logger.appendMsg(String.format("Skipped TLS NONAME variable with NID 0x%08X", varNID));
			}
			return;
		}
		
		final String defaultName = String.format("%s_%08X", _libName, varNID);
		String dbName = _ctx.nidDb.getVariableName(_libName, libraryNID, rawVarAddress);
		       
		final boolean isNewSymbol = (Utils.getSymbolAt(varAddr) == null);
		       
		Utils.createLabel(varAddr, defaultName, isNewSymbol);
		if (dbName != null) {
			//Like for functions, always set a database name as primary to avoid default name being primary in case of aliases.
			Utils.createLabel(varAddr, dbName, true);
		}      

		String variableComment = makeVariablePlateComment(varNID, isTLS);
		if (!isNewSymbol) {
			String oldComment = Utils.getPlateCommentAt(varAddr);
			if (oldComment != null) {
			 variableComment = oldComment + "\n\n" + variableComment;
			}  
		}      
		Utils.setPlateComment(varAddr, variableComment);
	}

	private void processNONAMEVariable(long varNID, Address varAddr) throws Exception {
		if (varNID == MODULE_INFO_NID) { //Parsing of ELFs begins by finding and parsing the SceModuleInfo - nothing to do
			return;
		} else if (varNID == MODULE_SDK_VERSION_NID) {
			Utils.createDataInNamespace(varAddr, _libNamespace, "module_sdk_version", TypeManager.getDataType("SceUInt32"));
			Utils.setPlateComment(varAddr, "Version of the SDK module was built with");
		} else if (varNID == PROCESS_PARAM_NID) {
			
			new SceProcessParam(_ctx, varAddr).apply();
			
		} else if (varNID == MODULE_DTRACE_PROBES_INFO_NID) {
			
			Utils.createDataInNamespace(varAddr, _libNamespace, "module_dtrace_probes_info", getProbesInfoDatatype());
			
			BinaryReader br = Utils.getMemoryReader(varAddr);
			long piVersion = br.readNextUnsignedInt();
			if (piVersion != 1L) {
				_ctx.logger.appendMsg(String.format("WARNING: static probes info version mismatch! (%d != %d)", piVersion, 1));
				return;
			}
			_numStaticProbes = (int)br.readNextUnsignedInt();
			
		} else if (varNID == MODULE_DTRACE_PROBES_NID) {
			
			_staticProbesAddr = varAddr;
			
		} else if (varNID == MODULE_START_THREAD_PARAMETER_NID) {
			
			new SceModuleThreadParameter(varAddr, ModuleThreadParameterType.MODULE_START_PARAMETER);
			
		} else if (varNID == MODULE_STOP_THREAD_PARAMETER_NID) {
			
			new SceModuleThreadParameter(varAddr, ModuleThreadParameterType.MODULE_STOP_PARAMETER);
			
		} else {
			Utils.createLabel(varAddr, String.format("NONAME_UnknownVariable_%08X", varNID), true);
			_ctx.logger.appendMsg(String.format("Module exports unknown NONAME variable with NID 0x%08X.", varNID));
		}
	}
	
/*
 * Gadgets
 */
	private static StructureDataType SDT_PROBES_INFO_TYPE = null;
	private DataType getProbesInfoDatatype() {
		if (SDT_PROBES_INFO_TYPE == null) {
			final DataType uint = UnsignedIntegerDataType.dataType;
			
			SDT_PROBES_INFO_TYPE = new StructureDataType(TypeManager.SCE_TYPES_CATPATH, "sdt_probes_info_t", 0);
			SDT_PROBES_INFO_TYPE.add(uint, "version", "");
			SDT_PROBES_INFO_TYPE.add(uint, "count", "");
		}
		
		return SDT_PROBES_INFO_TYPE;
	}
	
	private void processStaticProbes() throws Exception {
		if (_numStaticProbes == 0 && _staticProbesAddr == null) { //No static probes - everything is fine
			return;
		}
		
		if (_numStaticProbes != 0 && _staticProbesAddr == null) {
			_ctx.logger.appendMsg("WARNING: module exports static probes info, but no static probes!");
			return;
		}
		
		if (_numStaticProbes == 0 && _staticProbesAddr != null) {
			_ctx.logger.appendMsg("WARNING: module exports static probes, but no static probes info!");
			return;
		}
		
		Utils.createDataInNamespace(_staticProbesAddr, _libNamespace, "module_dtrace_probes", Utils.makeArray(new Pointer32DataType(sdt_probedesc_t.toDataType()), _numStaticProbes));

		
		BinaryReader probesArrayReader = Utils.getMemoryReader(_staticProbesAddr);
		int numProbesCounted = 0;
		for (int i = 0; i < (_numStaticProbes + 1 /* include NULL entry*/); i++) {
			long ptr = probesArrayReader.readNextUnsignedInt();
			if (ptr != 0L) {
				numProbesCounted += 1;
			} else {
				break;
			}
		}
		
		//Verify that size matches info.numProbes
		if (numProbesCounted != _numStaticProbes) {
			_ctx.logger.appendMsg(String.format("WARNING: mismatched static probes count (info->%d != %d)", _numStaticProbes, numProbesCounted));
			return;
		}
		
		probesArrayReader.setPointerIndex(0);
		for (int i = 0; i < _numStaticProbes; i++) {
			long ptr = probesArrayReader.readNextUnsignedInt();
			new sdt_probedesc_t(Utils.getProgramAddress(ptr));
		}
		
		if (_numStaticProbes > 1) {
			_ctx.logger.appendMsg(String.format("Module exports %d static probes.", _numStaticProbes));
		} else {
			_ctx.logger.appendMsg("Module exports 1 static probe.");
		}
	}
	
	/**
	 * 
	 * @param funcNid Function's NID
	 * @return Plate comment string
	 * @note CANNOT BE CALLED IF NONAME LIBRARY
	 */
	private String makeFunctionPlateComment(long funcNid) {
		String comment = "--- EXPORTED FUNCTION ---\n";
		comment += String.format("Library: %s (NID 0x%08X)\n", _libName, libraryNID);
		comment += String.format("Function NID: 0x%08X\n", funcNid);
		if (isSyscallExportLibrary()) {
			comment += "Syscall exported function\n";
		}
		comment += String.format("--- %s_%08X ---", _libName, funcNid);
		
		return comment;
	}
	
	/**
	 * 
	 * @param varNid Variable's NID
	 * @param isTLS Is variable a TLS variable?
	 * @return Plate comment string
	 * @note CANNOT BE CALLED IF NONAME LIBRARY
	 */
	private String makeVariablePlateComment(long varNid, boolean isTLS) {
		String comment = "--- EXPORTED " + ((isTLS) ? "TLS " : "") + "VARIABLE ---\n";
		comment += String.format("Library: %s (NID 0x%08X)\n", _libName, libraryNID);
		comment += String.format("Variable NID: 0x%08X\n", varNid);
		comment += String.format("--- %s_%08X ---", _libName, varNid);
		
		return comment;
	}
	
	private boolean isSyscallExportLibrary() {
		return ((attributes & 0x4000) != 0);
	}
	
	private boolean isNONAMELibrary() {
		return ((attributes & 0x8000) != 0);
	}
}
