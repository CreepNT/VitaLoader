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
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.program.model.mem.MemoryAccessException;

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
	private static final long MODULE_SDK_VERSION_NID 	= 0x936C8A78L; //uint
	private static final long PROCESS_PARAM_NID 		= 0x70FBA1E7L; //SceProcessParam
	private static final long PROCESSMGR_PROC_FUNC_EXPORT_DESCRIPTOR_NID = 0x9318D9DDL; //0x8 bytes structure that describes the size of array
	private static final long PROCESSMGR_PROC_FUNC_EXPORT_ARRAY_NID = 0x8CE938B1L; //Array of pointers to structures about ___proc__XXX functions exported by SceProcessmgr
	
	private static final String NAMELESS_LIBRARY_NAME = "__VITALOADER_NAMELESS_LIBRARY_NAME__";
	private ProcessingContext _ctx; //Processing context
	private Address _selfAddress; 	//Address we're located at
	private String _libraryName; 	//Name of the library those exports belong to
	
	private int _ProcessmgrProcFuncExportsArray_size = 0; //Number of entries in the array about ___proc__XXX functions
	private Address _ProcessmgrProcFuncExportsArray_address = null; //address of the array
	
	/**
	 * 
	 * @param ctx ELF processing context
	 * @param moduleExportsAddr Address this structure is located at 
	 * @param moduleName Name of the currently processed module
	 * @throws IOException
	 */
	public SceModuleExports(ProcessingContext ctx, Address moduleExportsAddr) 
			throws IOException, MemoryAccessException {
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
		_libraryName = NAMELESS_LIBRARY_NAME;
		
		//Parse library name if present
		if (this.library_name_ptr != 0L) {
			BinaryReader libNameReader = TypeHelper.getMemoryBackedBinaryReader(ctx.memory,
					ctx.textBlock.getStart().getNewAddress(this.library_name_ptr));
			_libraryName = libNameReader.readNextAsciiString();
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
		dt.add(WORD, "numTLSVars", "Number of TLS variables (maybe wrong)");
		dt.add(DWORD, "unk1", null);
		dt.add(DWORD, "libraryNID", "Numeric ID of library");
		dt.add(Pointer32DataType.dataType, "libraryName", "Pointer to library name");
		dt.add(Pointer32DataType.dataType, "pNIDTable", "Pointer to the table of all NIDs exported by this library");
		dt.add(Pointer32DataType.dataType, "pEntryTable", "Pointer to the table of all functions/variables exported by this library");
		
		if (dt.getLength() != SIZE)
			System.err.println("Unexpected " + NAME + " data type size (" + dt.getLength() + " != expected " + SIZE + " !)");

		//Cleanup area then apply structure
		_ctx.api.clearListing(_selfAddress, _selfAddress.add(dt.getLength()));
		_ctx.api.createData(_selfAddress, dt);
		
		if (_libraryName == NAMELESS_LIBRARY_NAME) //Not trusting library_name_ptr == 0L, because it's a public field
			_ctx.api.createLabel(_selfAddress, _ctx.moduleName + "_" + dt.getName(), true);
		else 
			_ctx.api.createLabel(_selfAddress, _ctx.moduleName + "_" + _libraryName + "_" + dt.getName(), true);
	}
	
	/**
	 * Processes the structure's content
	 */
	public void process() throws Exception {
		boolean isNamelessLib = this.isNamelessLibrary();
		String prettyLibName = (isNamelessLib) ? _ctx.moduleName + "_module" : _libraryName;
				
		//Create NID and entry tables
		Address nidTableAddress = _ctx.textBlock.getStart().getNewAddress(nid_table);
		Address entryTableAddress = _ctx.textBlock.getStart().getNewAddress(entry_table);

		_ctx.helper.createData(nidTableAddress, TypeHelper.makeArray(TypeHelper.u32, (num_functions + num_vars)));
		_ctx.helper.createData(entryTableAddress, TypeHelper.makeArray(Pointer32DataType.dataType, (num_functions + num_vars)));
		_ctx.api.createLabel(entryTableAddress, prettyLibName + "_exports_entry_table", true, SourceType.ANALYSIS);
		_ctx.api.createLabel(nidTableAddress, prettyLibName + "_exports_NID_table", true, SourceType.ANALYSIS);
		
		
		//Process exported functions
		if (num_functions > 0) {
			byte[] funcNidTableBytes = new byte[4 * num_functions];
			byte[] funcEntryTableBytes = new byte[4 * num_functions];
			_ctx.textBlock.getBytes(nidTableAddress, funcNidTableBytes);
			_ctx.textBlock.getBytes(entryTableAddress, funcEntryTableBytes);
			
			IntBuffer funcNidTable = ByteBuffer.wrap(funcNidTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
			IntBuffer funcEntryTable = ByteBuffer.wrap(funcEntryTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
			
			prepareMonitorProgressBar(_ctx.monitor, "Resolving function exports from " + prettyLibName + "...", num_functions);
			for (int i = 0; i < num_functions; i++, _ctx.monitor.incrementProgress(1)) {
				long funcNid = Integer.toUnsignedLong(funcNidTable.get(i));
				//Clear LSB, because functions have to start at a 2-byte boundary (i.e. ignore Thumb bit)
				long funcEntry = Integer.toUnsignedLong(funcEntryTable.get(i)) & ~1L;
				
				
				processFunction(prettyLibName, isNamelessLib, funcNid, funcEntry);
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
		
			prepareMonitorProgressBar(_ctx.monitor, "Resolving variable exports from " + prettyLibName + "...", num_vars);
			for (int i = 0; i < num_vars; i++, _ctx.monitor.incrementProgress(1)) {
				long varNid = Integer.toUnsignedLong(varNidTable.get(i));
				long varEntry = Integer.toUnsignedLong(varEntryTable.get(i));
				
				processVariable(prettyLibName, isNamelessLib, varNid, varEntry);
			}
		}
		_ctx.monitor.setShowProgressValue(false);
	}
	
	//Private routines used for processing
	private void processFunction(String libraryName, boolean isNamelessLib, 
			long functionNid, long functionEntry) 
					throws InvalidInputException, DuplicateNameException {
		String functionName = libraryName + String.format("_%08X", functionNid);
		Address functionEntryAddr = _ctx.textBlock.getStart().getNewAddress(functionEntry);
		
		if (isNamelessLib) {
			if (NAMELESS_FUNC_EXPORTS.containsKey((int)functionNid)) {
				functionName = NAMELESS_FUNC_EXPORTS.get((int)functionNid);
			}
			else {
				_ctx.logger.appendMsg(String.format("Unknown nameless function export NID 0x%08X", functionNid));
			}
		}
		else {
			String dbName = _ctx.nidDb.getFunctionName(this.library_nid, functionNid);
			if (dbName != null)
				functionName = dbName;
		}
		
		Function f = _ctx.api.getFunctionAt(functionEntryAddr);
		if (f == null) {
			boolean isEntrypoint = (isNamelessLib && (functionName.equals(MODULE_START_FUNC_NAME) || functionName.equals(MODULE_BOOTSTART_FUNC_NAME)));
			_ctx.helper.createOneByteFunction(functionName, functionEntryAddr, isEntrypoint);

			f = _ctx.api.getFunctionAt(functionEntryAddr);
			f.setSignatureSource(SourceType.ANALYSIS);
		} else {
			f.setName(functionName, SourceType.ANALYSIS);
		}
		
		if (!isNamelessLib) {
			f.setComment(String.format("Exported library name : %s\nFunction NID : 0x%08X\n---   %s_0x%08X   ---", libraryName, functionNid, libraryName, functionNid));
		}

		//Mark as exported
		//TODO, if possible: sort functions based on library name
		_ctx.program.getSymbolTable().addExternalEntryPoint(functionEntryAddr);
	}

	private void processVariable(String libraryName, boolean isNamelessLib,
			long variableNid, long variableAddress) throws Exception{
		String variableName = libraryName + String.format("_%08X", variableNid);
		Address varAddress = _ctx.textStart.getNewAddress(variableAddress);
		
		if (isNamelessLib) {
			//Before you come and say this is ugly or impractical and I should have used a Map:
			//I tried it, and you're wrong. If you still think I should have, try it yourself,
			//then blame yourself for wasting time on "making it faster and prettier" and not succeeding.
			
			//Can't use switch because NIDs are stored as long - thanks Java.
			if (variableNid == PROCESS_PARAM_NID) {
				SceProcessParam spp = new SceProcessParam(_ctx, varAddress);
				spp.apply();
			} else if (variableNid == MODULE_SDK_VERSION_NID) {
				_ctx.api.createData(varAddress, TypeHelper.u32);
				_ctx.api.createLabel(varAddress, _ctx.moduleName + "_module_SDK_version", true, SourceType.ANALYSIS);
			} else if (variableNid == MODULE_INFO_NID) {
				//No processing needed, SceModuleInfo class already did (we're sure of that because it calls us)
			} else if (variableNid == PROCESSMGR_PROC_FUNC_EXPORT_DESCRIPTOR_NID) {
				System.out.println("Processing DESCRIPTOR");
				
				_ctx.api.createData(varAddress, TypeHelper.makeArray(TypeHelper.u32, 2));
				_ctx.api.createLabel(varAddress, "SceProcessmgrProcFuncExportsInfo", true, SourceType.ANALYSIS);
				
				Address numFuncsAddr = varAddress.add(0x4);
				BinaryReader br = TypeHelper.getByteArrayBackedBinaryReader(_ctx, numFuncsAddr, 0x4);
				_ProcessmgrProcFuncExportsArray_size = (int)br.readNextUnsignedInt();
				markupProcFuncExportsIfPossible();
			} else if (variableNid == PROCESSMGR_PROC_FUNC_EXPORT_ARRAY_NID) {
				_ProcessmgrProcFuncExportsArray_address = varAddress;
				markupProcFuncExportsIfPossible();
			} else {
				_ctx.logger.appendMsg(String.format("Unknown nameless variable export NID 0x%08X", variableNid));
			}
			return;
		}
		
		String dbName = _ctx.nidDb.getVariableName(variableAddress, variableNid);
		if (dbName != null) 
			variableName = dbName;
		_ctx.api.createLabel(varAddress,  variableName, true, SourceType.ANALYSIS);
		//IF POSSIBLE - TODO: mark variable as exported
		//Maybe we could create a LibraryName_exports namespace or something ?
	}
	
/*
 * Gadgets
 */
	private void markupProcFuncExportsIfPossible() throws Exception {
		if (_ProcessmgrProcFuncExportsArray_size == 0 || _ProcessmgrProcFuncExportsArray_address == null) {
			return;
		}
		
		final Address arrAddr = _ProcessmgrProcFuncExportsArray_address;
		final int arrSize = _ProcessmgrProcFuncExportsArray_size;
		
		_ctx.api.createData(arrAddr, TypeHelper.makeArray(new Pointer32DataType(SceProcessmgrProcFuncExport.getDataType()), arrSize));
		_ctx.api.createLabel(arrAddr, "SceProcessmgrProcFuncExportsTable", true, SourceType.ANALYSIS);
		
		for (int i = 0; i < arrSize; i++) {
			Address ptrAddr = arrAddr.add(i * 4);
			BinaryReader ptrReader = TypeHelper.getByteArrayBackedBinaryReader(_ctx, ptrAddr, 4);
			long ptr = ptrReader.readNextUnsignedInt();
			
			Address structAddr = _ctx.textStart.getNewAddress(ptr);
			SceProcessmgrProcFuncExport table = new SceProcessmgrProcFuncExport(_ctx, structAddr);
			table.apply();
			table.process();
		}
		
	}
	
	private static void prepareMonitorProgressBar(TaskMonitor monitor, String msg, long max) {
		monitor.setShowProgressValue(false);
		monitor.setMessage(msg);
		monitor.setMaximum(max);
		monitor.setShowProgressValue(true);
	}
	
	private boolean isNamelessLibrary() {
		return (_libraryName == NAMELESS_LIBRARY_NAME);
	}
}
