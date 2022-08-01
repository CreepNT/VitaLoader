package vita.types;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.FunctionDefinitionDataType;

import vita.misc.TypeManager;
import vita.misc.Utils;
import vita.elf.VitaElfExtension.ProcessingContext;

public class TlsAllocReplacement {
	public long size;
	public long unk4;
	public long user_malloc_for_tls_init;
	public long user_malloc_for_tls_finalize;
	public long user_malloc_for_tls;
	public long user_free_for_tls;

	private final ProcessingContext _ctx;
	
	public static final int SIZE = 0x18;
	public static final String NAME = "SceLibcTlsAllocReplacement";
	
	private static CategoryPath TLS_REPLACEMENT_CATPATH = new CategoryPath(SceLibcParam_2xx.CATPATH, "TlsAllocReplacement");
	
	public TlsAllocReplacement(ProcessingContext ctx, Address libcxxAllocReplaceAddress, BinaryReader reader) throws Exception {
		_ctx = ctx;
		
		size = reader.readNextUnsignedInt();
		unk4 = reader.readNextUnsignedInt();
		user_malloc_for_tls_init = reader.readNextUnsignedInt();
		user_malloc_for_tls_finalize = reader.readNextUnsignedInt();
		user_malloc_for_tls = reader.readNextUnsignedInt();
		user_free_for_tls = reader.readNextUnsignedInt();
		
		if (size != SIZE) {
			Utils.appendLogMsg("Invalid TlsAllocReplacement size " + size + " (expected " + SIZE + ")");
			return;
		}
		
		//Apply structure
		Utils.createDataInNamespace(libcxxAllocReplaceAddress, Utils.getModuleNamespace(), "__sce_libcmallocreplacefortls", toDataType());
		
		//Markup functions
		__markup_if_present(this.user_malloc_for_tls_init, "user_malloc_for_tls_init", F_user_malloc_for_tls_init);
		__markup_if_present(this.user_malloc_for_tls_finalize, "user_malloc_for_tls_finalize", F_user_malloc_for_tls_finalize);
		__markup_if_present(this.user_malloc_for_tls, "user_malloc_for_tls", F_user_malloc_for_tls);
		__markup_if_present(this.user_free_for_tls, "user_free_for_tls", F_user_free_for_tls);
	}
	
	private static StructureDataType DATATYPE = null;
	private static FunctionDefinitionDataType F_user_malloc_for_tls_init = null;
	private static FunctionDefinitionDataType F_user_malloc_for_tls_finalize = null;
	private static FunctionDefinitionDataType F_user_malloc_for_tls = null;
	private static FunctionDefinitionDataType F_user_free_for_tls = null;

	public DataType toDataType() {
		if (DATATYPE == null) {
			final DataType size_t = new TypedefDataType("size_t", UnsignedIntegerDataType.dataType);
			final DataType pVoid = TypeManager.PVOID;
			final DataType uint = TypeManager.u32;
			final DataType VOID = new VoidDataType();
			
			//Create function signatures
			F_user_malloc_for_tls_init = fdef("user_malloc_for_tls_init", VOID, NOARGS);
			F_user_malloc_for_tls_finalize = fdef("user_malloc_for_tls_finalize", VOID, NOARGS);
			F_user_malloc_for_tls = fdef("user_malloc", pVoid, spdef("size", size_t));
			F_user_free_for_tls = fdef("user_free", new VoidDataType(), spdef("ptr", pVoid));
			
			
			DATATYPE = new StructureDataType(SceLibcParam_2xx.CATPATH, NAME, 0);
			DATATYPE.add(size_t, "size", "Size of this structure");
			DATATYPE.add(uint, "unk4", null);
			DATATYPE.add(new Pointer32DataType(F_user_malloc_for_tls_init), "Init", "Initialization function for TLS alloc replacement");
			DATATYPE.add(new Pointer32DataType(F_user_malloc_for_tls_finalize), "Finalize", "Finalization function for TLS alloc replacement");
			DATATYPE.add(new Pointer32DataType(F_user_malloc_for_tls), "mallocForTLS", "malloc_for_tls replacement function");
			DATATYPE.add(new Pointer32DataType(F_user_free_for_tls), "freeForTLS", "free_for_tls replacement function");
		}
		return DATATYPE;
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

	private void __markup_if_present(long address, String name, FunctionDefinitionDataType funcType) throws Exception {
		if (address == 0L)
			return;
		
		ParameterDefinition[] fArgs = funcType.getArguments();
		Function f = Utils.createFunction(name, address);
		f.setReturnType(funcType.getReturnType(), SourceType.ANALYSIS);
		if (fArgs.length > 0) {
			Variable[] vars = new Variable[fArgs.length];
			for (int i = 0; i < fArgs.length; i++) {
				vars[i] = new ParameterImpl(fArgs[i].getName(), fArgs[i].getDataType(), _ctx.program);
			}
			f.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS, vars);
		}
	}
}
