package vita.types;

import java.util.List;
import java.util.Arrays;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.util.ArrayList;
import java.nio.ByteBuffer;

import ghidra.util.task.TaskMonitor;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer32DataType;

import vita.misc.TypeHelper;
import vita.misc.ImportsManager;
import vita.elf.VitaElfExtension.ProcessingContext;

//Generic wrapper around SceModuleImports_1xx/SceModuleImports_3xx
public class GenericModuleImports {
	public static List<Integer> ValidSizes = new ArrayList<>(
			Arrays.asList(SceModuleImports_1xx.SIZE, SceModuleImports_3xx.SIZE)
	);
	
	public static boolean isImportsStructSizeValid(int size) {
		return ValidSizes.contains(size);
	}
	
	//Default name is specified in case library name is not specified, which *should* never happen.
	public String LibraryName = "((Paradox ERR))";	//Name of the imported library
	public long LibraryNID;		//Numeric ID of imported library
	public int NumFunctions;	//Number of functions imported from this library
	public long FuncNIDTable; 	//Offset to functions NID table
	public long FuncEntryTable;	//Offset to functions entrypoint table
	public int NumVariables;	//Number of variables imported from this library
	public long VarNIDTable; 	//Offset to variables NID table
	public long VarLocTable;	//Offset to variables table
	
	private ProcessingContext _ctx;
	
	public GenericModuleImports(ProcessingContext ctx, SceModuleImports_1xx imports) {
		_ctx = ctx;
		
		LibraryName = imports._LibraryName;
		LibraryNID = imports.library_nid;
		NumFunctions = imports.num_functions;
		FuncNIDTable = imports.func_nid_table;
		FuncEntryTable = imports.func_entry_table;
		NumVariables = imports.num_vars;
		VarNIDTable = imports.var_nid_table;
		VarLocTable = imports.var_entry_table;
	}
	
	public GenericModuleImports(ProcessingContext ctx, SceModuleImports_3xx imports) {
		_ctx = ctx;
		
		LibraryName = imports._LibraryName;
		LibraryNID = imports.library_nid;
		NumFunctions = imports.num_functions;
		FuncNIDTable = imports.func_nid_table;
		FuncEntryTable = imports.func_entry_table;
		NumVariables = imports.num_vars;
		VarNIDTable = imports.var_nid_table;
		VarLocTable = imports.var_entry_table;
	}
	
	public void process() throws Exception {
		ImportsManager impMgr = new ImportsManager(_ctx);
		//Process functions
		if (NumFunctions > 0){
			//Create NIDs and entry tables
			Address funcNidTableAddr = _ctx.textBlock.getStart().getNewAddress(FuncNIDTable);
			Address funcEntTableAddr = _ctx.textBlock.getStart().getNewAddress(FuncEntryTable);
			_ctx.helper.createSymbol(funcNidTableAddr, LibraryName + "_function_imports_NID_table", true, false, null);
			_ctx.helper.createSymbol(funcEntTableAddr, LibraryName + "_function_imports_entry_table", true, false, null);
			_ctx.helper.createData(funcNidTableAddr, TypeHelper.makeArray(TypeHelper.u32, NumFunctions));
			_ctx.helper.createData(funcEntTableAddr, TypeHelper.makeArray(Pointer32DataType.dataType, NumFunctions));

			
			byte[] funcNidTableBytes = new byte[4 * NumFunctions];
			byte[] funcEntTableBytes = new byte[4 * NumFunctions];
			_ctx.textBlock.getBytes(funcNidTableAddr, funcNidTableBytes);
			_ctx.textBlock.getBytes(funcEntTableAddr, funcEntTableBytes);

			IntBuffer funcNidTableIntBuffer = ByteBuffer.wrap(funcNidTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
			IntBuffer funcEntTableIntBuffer = ByteBuffer.wrap(funcEntTableBytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();

			prepareMonitorProgressBar(_ctx.monitor, "Resolving function imports from " + LibraryName + "...", NumFunctions);
			for (int i = 0; i < NumFunctions; i++, _ctx.monitor.incrementProgress(1)) {
				long funcNid =  Integer.toUnsignedLong(funcNidTableIntBuffer.get(i));
				//Clear LSB, because functions have to start at a 2-byte boundary (i.e. ignore Thumb bit)
				long funcEnt =  Integer.toUnsignedLong(funcEntTableIntBuffer.get(i)) & ~1L;
				
				//Process function
				Address functionEntryAddr = _ctx.textBlock.getStart().getNewAddress(funcEnt);
				impMgr.markupImportedFunction(LibraryName, LibraryNID, funcNid, functionEntryAddr);
			}
		}
		
		//Process variables
		if (NumVariables > 0){
			//Create NIDs and entry tables
			Address varNidTableAddr = _ctx.textBlock.getStart().getNewAddress(VarNIDTable);
			Address varEntTableAddr = _ctx.textBlock.getStart().getNewAddress(VarLocTable);
			_ctx.helper.createSymbol(varNidTableAddr, LibraryName + "_variable_imports_NID_table", true, false, null);
			_ctx.helper.createSymbol(varEntTableAddr, LibraryName + "_variable_imports_entry_table", true, false, null);
			_ctx.helper.createData(varNidTableAddr, TypeHelper.makeArray(TypeHelper.u32, NumVariables));
			_ctx.helper.createData(varEntTableAddr, TypeHelper.makeArray(Pointer32DataType.dataType, NumVariables));
		
			byte[] varNidTableBytes = new byte[4 * NumVariables];
			byte[] varEntTableBytes = new byte[4 * NumVariables];
			_ctx.textBlock.getBytes(varNidTableAddr, varNidTableBytes);
			_ctx.textBlock.getBytes(varEntTableAddr, varEntTableBytes);

			IntBuffer varNidTableIntBuffer = ByteBuffer.wrap(varNidTableBytes).order(TypeHelper.BYTE_ORDER).asIntBuffer();
			IntBuffer varEntTableIntBuffer = ByteBuffer.wrap(varEntTableBytes).order(TypeHelper.BYTE_ORDER).asIntBuffer();

			prepareMonitorProgressBar(_ctx.monitor, "Resolving variable imports from " + LibraryName + "...", NumFunctions);
			for (int i = 0; i < NumVariables; i++, _ctx.monitor.incrementProgress(1)) {
				long varNid =  Integer.toUnsignedLong(varNidTableIntBuffer.get(i));
				long varEnt =  Integer.toUnsignedLong(varEntTableIntBuffer.get(i));
				
				Address variableAddr = _ctx.textBlock.getStart().getNewAddress(varEnt);
				impMgr.markupImportedVariable(LibraryName, LibraryNID, varNid, variableAddr);
			}
		}
		_ctx.monitor.setShowProgressValue(false);
	}
	
	//Gadgets
	private static void prepareMonitorProgressBar(TaskMonitor monitor, String msg, long max) {
		monitor.setShowProgressValue(false);
		monitor.setMessage(msg);
		monitor.setMaximum(max);
		monitor.setShowProgressValue(true);
	}
}
