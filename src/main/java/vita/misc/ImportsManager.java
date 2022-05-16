package vita.misc;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.DuplicateNameException;

import vita.elf.VitaElfExtension.ProcessingContext;

public final class ImportsManager {
	private final ExternalManager _man;
	private final ProcessingContext _ctx;
	
	public ImportsManager(ProcessingContext ctx) {
		this._ctx = ctx;
		this._man = _ctx.program.getExternalManager();
	}

	public void markupImportedFunction(String libraryName, long libraryNid, long functionNid, Address functionAddress) throws Exception {
		String funcName = _ctx.nidDb.getFunctionName(libraryNid, functionNid);
		if (funcName == null) {
			funcName = String.format("%s_%08X", libraryName, functionNid);
		}

		/*Namespace ns =*/ getNamespaceFromLibName(libraryName); //Call to create libraries anyways
		Function f = _ctx.helper.createExternalFunctionLinkage(funcName, functionAddress, null);
		
		//TODO: add function to namespace somehow
		//Why did I not do it already ? Vita external functions are actually trunks in the ELF's .text block
		//What this means is that functionAddress.isExternal() is false
		//On the other hand, external libraries are (by definition) externals - namespace.isExternal() is true
		//Whenever you apply a namespace to a symbol, Ghidra will check that address.isExternal() == namespace.isExternal()
		//If you followed properly, you should see where the problem is.
		//I haven't figured out a way to mark a specific address as external, sadly.
		
		String funcComment = "--- IMPORTED FUNCTION ---\n";
		
		String fileName = getModuleFileNameFromLibName(libraryName);
		if (fileName != null) {
			funcComment += String.format("Imported from %s\n", fileName);
		} else {
			funcComment += "Imported from an unknown module!";
		}
		
		funcComment += String.format("Library: %s (NID 0x%08X)\n", libraryName);
		funcComment += String.format("Function NID: 0x%08X\n", functionNid);
		funcComment += String.format("--- %s_%08X ---", libraryName, functionNid);
		
		f.setComment(funcComment);
		
	}
	
	public void markupImportedVariable(String libraryName, long libraryNid, long variableNid, Address variableAddress) throws Exception {
		String variableName = libraryName + String.format("_%08X", variableNid);

		String dbName = _ctx.nidDb.getVariableName(libraryNid, variableNid);
		if (dbName != null)
			variableName = dbName;
		
		_ctx.api.clearListing(variableAddress);
		_ctx.api.createLabel(variableAddress, variableName, true, SourceType.IMPORTED);
		_ctx.program.getListing().setComment(variableAddress, CodeUnit.PLATE_COMMENT, String.format("Imported module file name : %s\nImported library name : %s\nVariable NID : 0x%08X\n---\t%s_%08X\t---", 
				getModuleFileNameFromLibName(libraryName), libraryName, variableNid, libraryName, variableNid));
	}
	
	private String getModuleFileNameFromLibName(String libraryName) {
		String modName = NameUtil.getModuleNameFromLibraryName(libraryName);
		if (modName == null) {
			return null;
		}
		
		String fileName = NameUtil.getFileNameFromModuleName(modName);
		if (fileName == null) {
			return null;
		}
		return fileName;
	}
	
	//Also creates the namespace if it doesn't exist yet
	private Namespace getNamespaceFromLibName(String libraryName) throws DuplicateNameException, InvalidInputException {
		String modName = NameUtil.getModuleNameFromLibraryName(libraryName);
		if (modName == null) {
			return _ctx.program.getGlobalNamespace();
		}
		
		String fileName = NameUtil.getFileNameFromModuleName(modName);
		if (fileName == null) {
			return _ctx.program.getGlobalNamespace();
		}
		Library lib = _man.getExternalLibrary(fileName);
		if (lib == null) {
			lib = _man.addExternalLibraryName(fileName, SourceType.IMPORTED); //_ctx.program.getSymbolTable().createExternalLibrary(fileName, SourceType.IMPORTED);
		}
		return lib;
	}
}
