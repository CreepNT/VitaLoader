package vita.types;

import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.nio.ByteBuffer;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.SourceType;
import vita.misc.TypeManager;
import vita.misc.Utils;
import vita.misc.NameUtil;
import vita.elf.VitaElfExtension.ProcessingContext;

//Generic wrapper around the multiple SceLibStubTable structures
public class GenericModuleImports {
	public String LibraryName; //Name of the imported library
	public long LibraryNID;	   //Numeric ID of imported library (-1 = none)
	
	//Functions
	public int NumFunctions;	//Number of functions imported from this library
	public long FuncNIDTable; 	//Offset to functions NID table
	public long FuncEntryTable;	//Offset to functions entrypoint table
	
	//Variables
	public int NumVariables;	//Number of variables imported from this library
	public long VarNIDTable; 	//Offset to variables NID table
	public long VarLocTable;	//Offset to variables location table
	
	//TLS variables
	public int NumTLSVars;		//Number of TLS variables imported from this library
	public long TLSNIDTable;	//Offset to TLS variables NID table
	public long TLSLocTable;	//Offset to TLS variables location table
	
	private ProcessingContext _ctx;
	private String fileName;
	
	public GenericModuleImports(ProcessingContext ctx, SceLibStubTable_0x2C imports) {
		_ctx = ctx;
		LibraryName = imports._LibraryName;
		LibraryNID = -1L;
		
		NumFunctions = imports.numFunctions;
		FuncNIDTable = imports.pFuncNidTbl;
		FuncEntryTable = imports.pFuncEntryTbl;
		
		NumVariables = imports.numVars;
		VarNIDTable = imports.pVarNidTbl;
		VarLocTable = imports.pVarEntryTbl;
		
		NumTLSVars = imports.numTlsVars;
		TLSNIDTable = imports.pTlsNidTbl;
		TLSLocTable = imports.pTlsEntryTbl;
	}
	
	public GenericModuleImports(ProcessingContext ctx, SceLibStubTable_0x34 imports) {
		_ctx = ctx;
		
		LibraryName = imports._LibraryName;
		LibraryNID = imports.library_nid;
		
		NumFunctions = imports.num_functions;
		FuncNIDTable = imports.func_nid_table;
		FuncEntryTable = imports.func_entry_table;
		
		NumVariables = imports.num_vars;
		VarNIDTable = imports.var_nid_table;
		VarLocTable = imports.var_entry_table;
		
		NumTLSVars = imports.num_syms_tls_vars;
		TLSNIDTable = imports.tls_nid_table;
		TLSLocTable = imports.tls_entry_table;
	}
	
	public GenericModuleImports(ProcessingContext ctx, SceLibStubTable_0x24 imports) {
		_ctx = ctx;
		
		LibraryName = imports._LibraryName;
		LibraryNID = imports.library_nid;
		
		NumFunctions = imports.num_functions;
		FuncNIDTable = imports.func_nid_table;
		FuncEntryTable = imports.func_entry_table;
		
		NumVariables = imports.num_vars;
		VarNIDTable = imports.var_nid_table;
		VarLocTable = imports.var_entry_table;
	
		NumTLSVars = imports.num_tls_variables;
		//TODO: is this correct?
		TLSNIDTable = VarNIDTable + 4 * NumVariables;
		TLSLocTable = VarLocTable + 4 * NumVariables;
	}
	
	public void process() throws Exception {
		String moduleName = NameUtil.getModuleNameFromLibraryName(LibraryName);
		if (moduleName != null) {
				fileName = NameUtil.getFileNameFromModuleName(moduleName);
		}

		final DataType SceUInt32 = TypeManager.getDataType("SceUInt32");
		
		//Process functions
		if (NumFunctions > 0) {
			Utils.prepareMonitorProgressBar(_ctx.monitor, "Resolving function imports from " + LibraryName + "...", NumFunctions);
			
			Address funcNidTableAddr = Utils.getProgramAddress(FuncNIDTable);
			Address funcEntTableAddr = Utils.getProgramAddress(FuncEntryTable);
			Utils.createDataInNamespace(funcNidTableAddr, LibraryName, "__" + LibraryName + "_func_nid_table", Utils.makeArray(SceUInt32, NumFunctions));
			Utils.createDataInNamespace(funcEntTableAddr, LibraryName, "__" + LibraryName + "_func_table", Utils.makeArray(Pointer32DataType.dataType, NumFunctions));
			
			byte[] funcNidTableBytes = new byte[4 * NumFunctions];
			byte[] funcEntTableBytes = new byte[4 * NumFunctions];
			Utils.getBytes(funcNidTableAddr, funcNidTableBytes);
			Utils.getBytes(funcEntTableAddr, funcEntTableBytes);

			IntBuffer funcNidTableIntBuffer = ByteBuffer.wrap(funcNidTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
			IntBuffer funcEntTableIntBuffer = ByteBuffer.wrap(funcEntTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();

			for (int i = 0; i < NumFunctions; i++, _ctx.monitor.incrementProgress(1)) {
				long funcNid =  Integer.toUnsignedLong(funcNidTableIntBuffer.get(i));
				long funcAddr =  Integer.toUnsignedLong(funcEntTableIntBuffer.get(i));
				
				String funcName = _ctx.nidDb.getFunctionName(LibraryNID, funcNid);
				if (funcName == null) {
					funcName = String.format("%s_%08X", LibraryName, funcNid);
				}

				Function func = Utils.createFunction(funcName, funcAddr, false);
				
				//Use the file names instead of library names to allow linking and allow
				//usage of LibraryName as namespace for data (i.e. SceLibStubTable)
				ExternalLocation ext = Utils.addExternalFunction(fileName, funcName);
				func.setThunkedFunction(ext.getFunction());
				func.setComment(makeFunctionPlateComment(funcNid));
			}
		}
		
		//Process variables
		/* TODO: from wiki
		 * Importing variables is a special case of imports. Function import points to the function table, whilst variable import points to the ELF relocation config in text segment.
		 *
		 *	typedef struct SceRelInfoType1Import {
		 *		SceSize size; // this object size << 4
		 *		SceRelInfoType1Variables info[];
		 *	} SceRelInfoType1Import;
		 */
		if (NumVariables > 0){
			Utils.prepareMonitorProgressBar(_ctx.monitor, "Resolving variable imports from " + LibraryName + "...", NumVariables);
			
			Address varNidTableAddr = Utils.getProgramAddress(VarNIDTable);
			Address varEntTableAddr = Utils.getProgramAddress(VarLocTable);
			Utils.createDataInNamespace(varNidTableAddr, LibraryName,  "__" + LibraryName + "_var_nid_table", Utils.makeArray(SceUInt32, NumVariables));
			Utils.createDataInNamespace(varEntTableAddr, LibraryName, "__" + LibraryName + "_var_table", Utils.makeArray(Pointer32DataType.dataType, NumVariables));
		
			byte[] varNidTableBytes = new byte[4 * NumVariables];
			byte[] varEntTableBytes = new byte[4 * NumVariables];
			Utils.getBytes(varNidTableAddr, varNidTableBytes);
			Utils.getBytes(varEntTableAddr, varEntTableBytes);

			IntBuffer varNidTableIntBuffer = ByteBuffer.wrap(varNidTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
			IntBuffer varEntTableIntBuffer = ByteBuffer.wrap(varEntTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();

			for (int i = 0; i < NumVariables; i++, _ctx.monitor.incrementProgress(1)) {
				long varNid =  Integer.toUnsignedLong(varNidTableIntBuffer.get(i));
				long varEnt =  Integer.toUnsignedLong(varEntTableIntBuffer.get(i));
				
				Address varAddr = Utils.getProgramAddress(varEnt);
				
				String defaultName = String.format("%s_%08X", LibraryName, varNid);
				String dbName = _ctx.nidDb.getVariableName(LibraryNID, varNid);
				
				_ctx.api.clearListing(varAddr);
				if (dbName != null) { //Use database name as primary if it exists
					_ctx.api.createLabel(varAddr, dbName, true, SourceType.ANALYSIS);
					_ctx.api.createLabel(varAddr, defaultName, false, SourceType.ANALYSIS);
				} else {
					_ctx.api.createLabel(varAddr, defaultName, true, SourceType.ANALYSIS);
				}
				
				_ctx.program.getListing().setComment(varAddr, CodeUnit.PLATE_COMMENT, makeVariablePlateComment(varNid, false));
			}
		}
		
		//Process TLS variables
		if (NumTLSVars > 0) {
			Utils.prepareMonitorProgressBar(_ctx.monitor, "Resolving TLS variable imports from " + LibraryName + "...", NumTLSVars);
			
			Address varNidTableAddr = Utils.getProgramAddress(TLSNIDTable);
			Address varEntTableAddr = Utils.getProgramAddress(TLSLocTable);
			//TODO: correct name
			Utils.createDataInNamespace(varNidTableAddr, LibraryName, "TLSVariablesNIDTable",   Utils.makeArray(SceUInt32, NumTLSVars));
			Utils.createDataInNamespace(varEntTableAddr, LibraryName, "TLSVariablesEntryTable", Utils.makeArray(Pointer32DataType.dataType, NumTLSVars));
		
			byte[] varNidTableBytes = new byte[4 * NumTLSVars];
			byte[] varEntTableBytes = new byte[4 * NumTLSVars];
			Utils.getBytes(varNidTableAddr, varNidTableBytes);
			Utils.getBytes(varEntTableAddr, varEntTableBytes);

			IntBuffer varNidTableIntBuffer = ByteBuffer.wrap(varNidTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
			IntBuffer varEntTableIntBuffer = ByteBuffer.wrap(varEntTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();

			for (int i = 0; i < NumTLSVars; i++, _ctx.monitor.incrementProgress(1)) {
				long varNid =  Integer.toUnsignedLong(varNidTableIntBuffer.get(i));
				long varEnt =  Integer.toUnsignedLong(varEntTableIntBuffer.get(i));
				
				Address varAddr = Utils.getProgramAddress(varEnt);
				
				String defaultName = String.format("%s_%08X", LibraryName, varNid);
				String dbName = _ctx.nidDb.getVariableName(LibraryNID, varNid);
				
				_ctx.api.clearListing(varAddr);
				if (dbName != null) { //Use database name as primary if it exists
					_ctx.api.createLabel(varAddr, dbName, true, SourceType.ANALYSIS);
					_ctx.api.createLabel(varAddr, defaultName, false, SourceType.ANALYSIS);
				} else {
					_ctx.api.createLabel(varAddr, defaultName, true, SourceType.ANALYSIS);
				}
				
				_ctx.program.getListing().setComment(varAddr, CodeUnit.PLATE_COMMENT, makeVariablePlateComment(varNid, true));
			}
		}
		
		_ctx.monitor.setShowProgressValue(false);
	}
	
	private String makeFunctionPlateComment(long funcNid) {
		String comment = "--- IMPORTED FUNCTION ---\n";
		if (fileName != null) {
			comment += String.format("Imported from %s\n", fileName);
		} else {
			comment += "Imported from unknown module!\n";
		}
		
		if (LibraryNID != -1L) {
			comment += String.format("Library: %s (NID 0x%08X)\n", LibraryName, LibraryNID);
		} else {
			comment += "Library: " + LibraryName + "\n";
		}
		
		comment += String.format("Function NID: 0x%08X\n", funcNid);
		comment += String.format("--- %s_%08X ---", LibraryName, funcNid);
		
		return comment;
	}
	
	private String makeVariablePlateComment(long varNid, boolean isTLS) {
		String comment = "--- IMPORTED " + ((isTLS) ? "TLS " : "") + "VARIABLE ---\n";
		if (fileName != null) {
			comment += String.format("Imported from %s\n", fileName);
		} else {
			comment += "Imported from unknown module!\n";
		}
		
		if (LibraryNID != -1L) {
			comment += String.format("Library: %s (NID 0x%08X)\n", LibraryName, LibraryNID);
		} else {
			comment += "Library: " + LibraryName + "\n";
		}
		
		comment += String.format("Variable NID: 0x%08X\n", varNid);
		comment += String.format("--- %s_%08X ---", LibraryName, varNid);
		
		return comment;
	}
}
