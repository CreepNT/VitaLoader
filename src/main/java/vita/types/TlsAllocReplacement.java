package vita.types;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.FunctionDefinitionDataType;

import vita.misc.TypeHelper;
import vita.elf.VitaElfExtension.ProcessingContext;

public class TlsAllocReplacement implements StructConverter {
	public long size;
	public long unk4;
	public long user_malloc_for_tls_init;
	public long user_malloc_for_tls_finalize;
	public long user_malloc_for_tls;
	public long user_free_for_tls;
	private final ProcessingContext _ctx;
	private final Address _selfAddress;
	public static final int SIZE = 0x18;
	public static final String NAME = "SceLibcTlsAllocReplacement";

	private static CategoryPath TLS_REPLACEMENT_CATPATH = new CategoryPath(TypeHelper.SCE_TYPES_CATPATH, "TlsAllocReplacement");
	
	public TlsAllocReplacement(ProcessingContext ctx, Address libcxxAllocReplaceAddress, BinaryReader reader) throws IOException {
		size = reader.readNextUnsignedInt();
		unk4 = reader.readNextUnsignedInt();
		user_malloc_for_tls_init = reader.readNextUnsignedInt();
		user_malloc_for_tls_finalize = reader.readNextUnsignedInt();
		user_malloc_for_tls = reader.readNextUnsignedInt();
		user_free_for_tls = reader.readNextUnsignedInt();
		
		_ctx = ctx;
		_selfAddress = libcxxAllocReplaceAddress;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}

	public void apply() throws Exception {
		//Local declarations for convenience
		DataType size_t = TypeHelper.size_t;
		DataType pVoid = TypeHelper.PVOID;
		DataType uint = TypeHelper.u32;
		
		//Create function signatures
		FunctionDefinitionDataType F_user_malloc_for_tls_init = fdef("user_malloc_for_tls_init", VOID, NOARGS);
		FunctionDefinitionDataType F_user_malloc_for_tls_finalize = fdef("user_malloc_for_tls_finalize", VOID, NOARGS);
		FunctionDefinitionDataType F_user_malloc_for_tls = fdef("user_malloc", pVoid, spdef("size", size_t));
		FunctionDefinitionDataType F_user_free_for_tls = fdef("user_free", VOID, spdef("ptr", pVoid));

		//Create the structure itself
		StructureDataType tls_alloc_replace_struct = TypeHelper.createAndGetStructureDataType(TLS_REPLACEMENT_CATPATH, NAME);
		tls_alloc_replace_struct.add(size_t, "size", "Size of this structure");
		tls_alloc_replace_struct.add(uint, "unk4", null);
		tls_alloc_replace_struct.add(new Pointer32DataType(F_user_malloc_for_tls_init), "Init", "Initialization function for TLS alloc replacement");
		tls_alloc_replace_struct.add(new Pointer32DataType(F_user_malloc_for_tls_finalize), "Finalize", "Finalization function for TLS alloc replacement");
		tls_alloc_replace_struct.add(new Pointer32DataType(F_user_malloc_for_tls), "mallocForTLS", "malloc_for_tls replacement function");
		tls_alloc_replace_struct.add(new Pointer32DataType(F_user_free_for_tls), "freeForTLS", "free_for_tls replacement function");
		
		if (tls_alloc_replace_struct.getLength() != SIZE)
			System.err.println("Unexpected " + NAME + " data type size (" + tls_alloc_replace_struct.getLength() + " != expected " + SIZE + " !)");
		
		//Apply structure
		_ctx.api.clearListing(_selfAddress);
		_ctx.api.createData(_selfAddress, tls_alloc_replace_struct);
		_ctx.api.createLabel(_selfAddress, _ctx.moduleName + "_" + tls_alloc_replace_struct.getName(), true);
	
		//Markup functions
		__markup_if_present(this.user_malloc_for_tls_init, "user_malloc_for_tls_init", F_user_malloc_for_tls_init);
		__markup_if_present(this.user_malloc_for_tls_finalize, "user_malloc_for_tls_finalize", F_user_malloc_for_tls_finalize);
		__markup_if_present(this.user_malloc_for_tls, "user_malloc_for_tls", F_user_malloc_for_tls);
		__markup_if_present(this.user_free_for_tls, "user_free_for_tls", F_user_free_for_tls);
	}
	
	private static final ParameterDefinition[] NOARGS = new ParameterDefinition[]{};
	
	//Macro-like to generate Single Parameter DEFinition array (1-element array)
	private ParameterDefinition[] spdef(String argName, DataType argType) {
		return pdef(new String[] {argName}, new DataType[] {argType});
	}
	
	//Macro-like to generate Parameter DEFinition array
	private ParameterDefinition[] pdef(String[] argNames, DataType[] argTypes) {
		if (argNames.length != argTypes.length) {
			System.err.println(String.format("Mismatching length %d != %d in pdef() !", argNames.length, argTypes.length));
			return null;
		}
		
		ParameterDefinition[] ret = new ParameterDefinition[argNames.length];
		for (int i = 0; i < argNames.length; i++) {
			ret[i] = new ParameterDefinitionImpl(argNames[i], argTypes[i], null);
		}
		return ret;
	}
	
	
	//Macro-like to generate a Function DEFinition
	private FunctionDefinitionDataType fdef(String name, DataType returnType, ParameterDefinition[] args) {
		FunctionDefinitionDataType r = new FunctionDefinitionDataType(TLS_REPLACEMENT_CATPATH, name);
		r.setReturnType(returnType);
		r.setArguments(args);
		return r;
	}

	private void __markup_if_present(long address, String name, FunctionDefinitionDataType function) throws Exception {
		if (address == 0L)
			return;
		
		ParameterDefinition[] fArgs = function.getArguments();
		Function f = _ctx.helper.createOneByteFunction(name, _ctx.textStart.getNewAddress(address), false);
		f.setReturnType(function.getReturnType(), SourceType.ANALYSIS);
		if (fArgs.length > 0) {
			Variable[] vars = new Variable[fArgs.length];
			for (int i = 0; i < fArgs.length; i++) {
				vars[i] = new ParameterImpl(fArgs[i].getName(), fArgs[i].getDataType(), _ctx.program);
			}
			f.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS, vars);
		}
	}
}
