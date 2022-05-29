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
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TerminatedStringDataType;
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
	//On old firmware, library NID is after the last entry in entry table 
	public long pNidTbl;
	public long pEntryTbl;

	private final ProcessingContext _ctx; 	//Processing context
	private final Address _selfAddress; 	//Address this structure is located at
	
	private final String 	_libName; 		//Name of this library
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
			0xE640E30C, "ModuleEntryType0",
			0x4F0EE5BD, "ModuleEntryType1",
			0xDF0212B9, "ModuleEntryType2",
			0xDD42FA37, "module_entry_DD42FA37"
	);
	
	private static final long MODULE_SDK_VERSION_NID 	= 0x936C8A78L; //SceUInt32
	private static final long MODULE_INFO_NID 			= 0x6C2224BAL; //SceModuleInfo
	
	private static final long PROCESS_PARAM_NID 		= 0x70FBA1E7L; //SceProcessParam
	
	private static final long STATIC_PROBES_INFO_NID = 0x9318D9DDL;
	private static final long STATIC_PROBES_ARRAY_NID = 0x8CE938B1L;
	
	//SceModuleThreadParameter
	private static final long MODULE_START_THREAD_PARAMETER_NID = 0x1A9822A4L;
	private static final long MODULE_STOP_THREAD_PARAMETER_NID = 0xD20886EBL;
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
		} else if (size == 0x1C) {
			libraryNID = 0xFFFFFFFFL;
		} else {
			throw new RuntimeException(String.format("Unknown SceModuleExports with size 0x%08X!", size));
		}
		
		pLibName 	= reader.readNextUnsignedInt();
		pNidTbl 	= reader.readNextUnsignedInt();
		pEntryTbl 	= reader.readNextUnsignedInt();

		_numExports = numFuncs + numVars + numTLSVars;
		
		//Parse library name if present
		if (this.pLibName != 0L) {
			Address libNameAddress = Utils.getProgramAddress(this.pLibName);
			BinaryReader libNameReader = Utils.getMemoryReader(libNameAddress);
			_libName = libNameReader.readNextAsciiString();
			_libNamespace = Utils.getNamespaceFromName(_libName);
			
			Utils.createDataInNamespace(libNameAddress, _libNamespace, "_" + _libName + "_str", new TerminatedStringDataType());
			
			if (isNONAMELibrary()) {
				Utils.appendLogMsg(String.format("WARNING: NONAME library has a name! (name=%s)", _libName));
			}
			_libNamespace = Utils.getNamespaceFromName(_libName);
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
		final String defaultName = String.format("%s_%08X", _libName, functionNid);
		String dbName = null;
		String funcComment = makeFunctionPlateComment(functionNid);
		Address funcAddr = Utils.getProgramAddress(functionEntry & ~1L); //LSB is always clear for a function
		
		if (!isNONAMELibrary()) {
			dbName = _ctx.nidDb.getFunctionName(libraryNID, functionNid);
		} else {
			if (NAMELESS_FUNC_EXPORTS.containsKey((int)functionNid)) {
				dbName = NAMELESS_FUNC_EXPORTS.get((int)functionNid);
			}
			else {
				_ctx.logger.appendMsg(String.format("Module exports unknown NONAME function with NID 0x%08X.", functionNid));
			}
		}
		
		//See if function already exists
		Function func = _ctx.api.getFunctionAt(funcAddr);
		if (func != null) { //Already exists - append comment and add names as secondary labels, and markup TMode
			func = Utils.createFunction(defaultName, functionEntry, false); //TMode + add default name label
			if (dbName != null) {
				_ctx.api.createLabel(funcAddr, dbName, false, SourceType.ANALYSIS);
			}
			
			String previousComment = func.getComment();
			if (previousComment != null) {
				funcComment = previousComment + "\n\n" + funcComment;
			}			
		} else { //Function doesn't exist - create it
			if (dbName == null) {
				func = Utils.createFunction(defaultName, functionEntry, true);
			} else {
				//Use DB name as primary name, and default name as secondary label
				func = Utils.createFunction(dbName, functionEntry, true);
				
				//Don't apply default name for NONAME functions
				if (!isNONAMELibrary()) {
					_ctx.api.createLabel(funcAddr, defaultName, false, SourceType.ANALYSIS);
				}
			}
		}
		
		if (!isNONAMELibrary()) { //Don't add comment to NONAME functions
			func.setComment(funcComment);
		}
		
		//It doesn't seem possible to sort functions based on library name (without using namespaces, which imo defeats the purpose), so leave as-is
	}

	private void processVariable(long varNID, long rawVarAddress, boolean isTLS) throws Exception {
		Address varAddr = Utils.getProgramAddress(rawVarAddress);
		if (!isNONAMELibrary()) {
			String defaultName = String.format("%s_%08X", _libName, varNID);
			String dbName = _ctx.nidDb.getVariableName(libraryNID, rawVarAddress);
			
			if (_ctx.api.getSymbolAt(varAddr) == null) { //No symbol exists - create new
				if (dbName != null) { //Use database name as primary label, then default as secondary
					_ctx.api.createLabel(varAddr, dbName, true, SourceType.ANALYSIS);
					_ctx.api.createLabel(varAddr, defaultName, false, SourceType.ANALYSIS);
				} else {
					_ctx.api.createLabel(varAddr, defaultName, true, SourceType.ANALYSIS);
				}
				_ctx.api.setPlateComment(varAddr, makeVariablePlateComment(varNID, isTLS));
				
			} else { //Symbol exists - append new labels
				if (dbName != null) { //Use database name as primary label, then default as secondary
					_ctx.api.createLabel(varAddr, dbName, true, SourceType.ANALYSIS);
					_ctx.api.createLabel(varAddr, defaultName, false, SourceType.ANALYSIS);
				} else {
					_ctx.api.createLabel(varAddr, defaultName, true, SourceType.ANALYSIS);
				}
				_ctx.api.setPlateComment(varAddr, _ctx.api.getPlateComment(varAddr) + "\n\n" + makeVariablePlateComment(varNID, isTLS));
			}
		} else { //NONAME library
			//TODO make this cleaner
			
			if (varNID == MODULE_INFO_NID) { //Parsing of ELFs begins by finding and parsing the SceModuleInfo, so nothing to do
				return;
			} else if (varNID == MODULE_SDK_VERSION_NID) {
				Utils.createDataInNamespace(varAddr, _libNamespace, "__crt0_main_sdk_version_var", TypeManager.getDataType("SceUInt32"));
				_ctx.api.setPlateComment(varAddr, "Version of the SDK this module was linked against");
			} else if (varNID == PROCESS_PARAM_NID) {
				
				new SceProcessParam(_ctx, varAddr).apply();
				
			} else if (varNID == STATIC_PROBES_INFO_NID) {
				
				Utils.createDataInNamespace(varAddr, _libNamespace, "static_probes_info", getStaticProbesInfoDataType());
				
				BinaryReader br = Utils.getMemoryReader(varAddr);
				long piVersion = br.readNextUnsignedInt();
				if (piVersion != 1L) {
					_ctx.logger.appendMsg(String.format("WARNING: static probes info version mismatch! (%d != %d)", piVersion, 1));
					return;
				}
				_numStaticProbes = (int)br.readNextUnsignedInt();
				
			} else if (varNID == STATIC_PROBES_ARRAY_NID) {
				
				_staticProbesAddr = varAddr;
				
			} else if (varNID == MODULE_START_THREAD_PARAMETER_NID) {
				
				new SceModuleThreadParameter(varAddr, ModuleThreadParameterType.MODULE_START_PARAMETER);
				
			} else if (varNID == MODULE_STOP_THREAD_PARAMETER_NID) {
				
				new SceModuleThreadParameter(varAddr, ModuleThreadParameterType.MODULE_STOP_PARAMETER);
				
			} else {
				_ctx.api.createLabel(varAddr, String.format("NONAME_UnknownVariable_%08X", varNID), true, SourceType.ANALYSIS);
				_ctx.api.setPlateComment(varAddr, makeVariablePlateComment(varNID, isTLS));
				
				_ctx.logger.appendMsg(String.format("Module exports unknown NONAME variable with NID 0x%08X.", varNID));
			}
		}
	}
	
/*
 * Gadgets
 */
	private static StructureDataType STATIC_PROBES_INFO_DT = null;
	private DataType getStaticProbesInfoDataType() {
		if (STATIC_PROBES_INFO_DT != null) {
			return STATIC_PROBES_INFO_DT;
		}
		
		final DataType SceUInt32 = TypeManager.getDataType("SceUInt32");
		
		STATIC_PROBES_INFO_DT = new StructureDataType(TypeManager.SCE_TYPES_CATPATH, "SceModuleStaticProbesInfo", 0);
		STATIC_PROBES_INFO_DT.add(SceUInt32, "version", "Version of the static probes");
		STATIC_PROBES_INFO_DT.add(SceUInt32, "numProbes", "Number of static probes exported");
		
		return STATIC_PROBES_INFO_DT;
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
		
		Utils.createDataInNamespace(_staticProbesAddr, _libNamespace, "static_probes", Utils.makeArray(new Pointer32DataType(SceModuleStaticProbe.toDataType()), _numStaticProbes));

		
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
			new SceModuleStaticProbe(Utils.getProgramAddress(ptr));
		}
		
		_ctx.logger.appendMsg(String.format("Module exports %d static probe(s).", _numStaticProbes));
		
	}
	
	private String makeFunctionPlateComment(long funcNid) {
		String comment = "--- EXPORTED FUNCTION ---\n";
		if (size == 0x20) {
			comment += String.format("Library: %s (NID 0x%08X)\n", _libName, libraryNID);
		} else {
			comment += "Library: " + _libName + "\n";
		}
		
		comment += String.format("Function NID: 0x%08X\n", funcNid);
		if (isUserImportableLibrary()) {
			comment += "User-importable function\n";
		}
		comment += String.format("--- %s_%08X ---", _libName, funcNid);
		
		return comment;
	}
	
	private String makeVariablePlateComment(long varNid, boolean isTLS) {
		String comment = "--- EXPORTED " + ((isTLS) ? "TLS " : "") + "VARIABLE ---\n";
		if (size == 0x20) {
			comment += String.format("Library: %s (NID 0x%08X)\n", _libName, libraryNID);
		} else {
			comment += "Library: " + _libName + "\n";
		}
		
		comment += String.format("Variable NID: 0x%08X\n", varNid);
		comment += String.format("--- %s_%08X ---", _libName, varNid);
		
		return comment;
	}
	
	private boolean isUserImportableLibrary() {
		return ((attributes & 0x4000) != 0);
	}
	
	private boolean isNONAMELibrary() {
		return ((attributes & 0x8000) != 0);
	}
}
