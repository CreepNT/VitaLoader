package vita.types;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.FunctionDefinitionDataType;

import vita.misc.TypeManager;
import vita.misc.Utils;
import vita.elf.VitaElfExtension.ProcessingContext;

public class LibcAllocReplacement implements StructConverter {
	public long size;
	public long unk4;
	public long user_malloc_init;
	public long user_malloc_finalize;
	public long user_malloc;
	public long user_free;
	public long user_calloc;
	public long user_realloc;
	public long user_memalign;
	public long user_reallocalign;
	public long user_malloc_stats;
	public long user_malloc_stats_fast;
	public long user_malloc_usable_size;
	private final ProcessingContext _ctx;
	private final Address _selfAddress;
	public static final int SIZE = 0x34;
	public static final String NAME = "SceLibcAllocReplacement";
	
	private static CategoryPath LIBC_REPLACEMENT_CATPATH = new CategoryPath(SceLibcParam_2xx.CATPATH, "LibcAllocReplacement");
	
	public LibcAllocReplacement(ProcessingContext ctx, Address libcAllocReplaceAddress, BinaryReader reader) throws IOException {
		size = reader.readNextUnsignedInt();
		unk4 = reader.readNextUnsignedInt();
		user_malloc_init = reader.readNextUnsignedInt();
		user_malloc_finalize = reader.readNextUnsignedInt();
		user_malloc = reader.readNextUnsignedInt();
		user_free = reader.readNextUnsignedInt();
		user_calloc = reader.readNextUnsignedInt();
		user_realloc = reader.readNextUnsignedInt();
		user_memalign = reader.readNextUnsignedInt();
		user_reallocalign = reader.readNextUnsignedInt();
		user_malloc_stats = reader.readNextUnsignedInt();
		user_malloc_stats_fast = reader.readNextUnsignedInt();
		user_malloc_usable_size = reader.readNextUnsignedInt();
		
		_ctx = ctx;
		_selfAddress = libcAllocReplaceAddress;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}

	
	public void apply() throws Exception {
		//Local declarations for convenience
		final DataType size_t = new TypedefDataType("size_t", UnsignedIntegerDataType.dataType);
		final DataType pVoid = TypeManager.PVOID;
		final DataType sint = TypeManager.s32;
		final DataType uint = TypeManager.u32;
		
		//Create malloc_managed_size struct
		StructureDataType mmsize = new StructureDataType(LIBC_REPLACEMENT_CATPATH, "malloc_managed_size", 8 * 4);
		mmsize.add(size_t, "max_system_size", null);
		mmsize.add(size_t, "current_system_size", null);
		mmsize.add(size_t, "max_inuse_size", null);
		mmsize.add(size_t, "current_inuse_size", null);
		mmsize.add(new ArrayDataType(size_t, 4, size_t.getLength()), "reserved", "Reserved area");
		DataType pmmsize = new Pointer32DataType(mmsize);
		
		//Create function signatures
		FunctionDefinitionDataType F_user_malloc_init 		= fdef("user_malloc_init", VOID, NOARGS);
		FunctionDefinitionDataType F_user_malloc_finalize 	= fdef("user_malloc_finalize", VOID, NOARGS);
		FunctionDefinitionDataType F_user_malloc 			= fdef("user_malloc", pVoid, spdef("size", size_t));
		FunctionDefinitionDataType F_user_free 				= fdef("user_free", VOID, spdef("ptr", pVoid));
		FunctionDefinitionDataType F_user_calloc 			= fdef("user_calloc", pVoid, pdef(new String[]{"nelem", "size"}, new DataType[]{size_t, size_t}));
		FunctionDefinitionDataType F_user_realloc 			= fdef("user_realloc", pVoid, pdef(new String[]{"ptr", "size"}, new DataType[]{pVoid, size_t}));
		FunctionDefinitionDataType F_user_memalign 			= fdef("user_memalign", pVoid, pdef(new String[]{"boundary", "size"}, new DataType[]{size_t, size_t}));
		FunctionDefinitionDataType F_user_reallocalign 		= fdef("user_reallocalign", pVoid, pdef(new String[]{"ptr", "size", "boundary"}, new DataType[]{pVoid, size_t, size_t}));
		FunctionDefinitionDataType F_user_malloc_stats 		= fdef("user_malloc_stats", sint, spdef("mmsize", pmmsize));
		FunctionDefinitionDataType F_user_malloc_stats_fast = fdef("user_malloc_stats_fast", sint, spdef("mmsize", pmmsize));
		FunctionDefinitionDataType F_user_malloc_usable_size = fdef("user_malloc_usable_size", size_t, spdef("ptr", pVoid));

		//Create the structure itself
		StructureDataType libc_alloc_replace_struct = new StructureDataType(SceLibcParam_2xx.CATPATH, NAME, 0);
		libc_alloc_replace_struct.add(size_t, "size", "Size of this structure");
		libc_alloc_replace_struct.add(uint, "unk4", null);
		libc_alloc_replace_struct.add(new Pointer32DataType(F_user_malloc_init));
		libc_alloc_replace_struct.add(new Pointer32DataType(F_user_malloc_finalize));
		libc_alloc_replace_struct.add(new Pointer32DataType(F_user_malloc));
		libc_alloc_replace_struct.add(new Pointer32DataType(F_user_free));
		libc_alloc_replace_struct.add(new Pointer32DataType(F_user_calloc));
		libc_alloc_replace_struct.add(new Pointer32DataType(F_user_realloc));
		libc_alloc_replace_struct.add(new Pointer32DataType(F_user_memalign));
		libc_alloc_replace_struct.add(new Pointer32DataType(F_user_reallocalign));
		libc_alloc_replace_struct.add(new Pointer32DataType(F_user_malloc_stats));
		libc_alloc_replace_struct.add(new Pointer32DataType(F_user_malloc_stats_fast));
		libc_alloc_replace_struct.add(new Pointer32DataType(F_user_malloc_usable_size));
		
		if (libc_alloc_replace_struct.getLength() != SIZE)
			System.err.println("Unexpected " + NAME + " data type size (" + libc_alloc_replace_struct.getLength() + " != expected " + SIZE + " !)");
		
		Utils.createDataInNamespace(_selfAddress, Utils.getModuleName(), NAME, libc_alloc_replace_struct);
		
		//Markup functions
		__markup_if_present(this.user_malloc_init, "user_malloc_init", F_user_malloc_init);
		__markup_if_present(this.user_malloc_finalize, "user_malloc_finalize", F_user_malloc_finalize);
		__markup_if_present(this.user_malloc, "user_malloc", F_user_malloc);
		__markup_if_present(this.user_free, "user_free", F_user_free);
		__markup_if_present(this.user_calloc, "user_calloc", F_user_calloc);
		__markup_if_present(this.user_realloc, "user_realloc", F_user_realloc);
		__markup_if_present(this.user_memalign, "user_memalign", F_user_memalign);
		__markup_if_present(this.user_reallocalign, "user_reallocalign", F_user_reallocalign);
		__markup_if_present(this.user_malloc_stats, "user_malloc_stats", F_user_malloc_stats);
		__markup_if_present(this.user_malloc_stats_fast, "user_malloc_stats_fast", F_user_malloc_stats_fast);
		__markup_if_present(this.user_malloc_usable_size, "user_malloc_usable_size", F_user_malloc_usable_size);
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
		FunctionDefinitionDataType r = new FunctionDefinitionDataType(LIBC_REPLACEMENT_CATPATH, name);
		r.setReturnType(returnType);
		r.setArguments(args);
		return r;
	}
	
	private void __markup_if_present(long address, String name, FunctionDefinitionDataType funcType) throws Exception {
		if (address == 0L)
			return;
		
		ParameterDefinition[] fArgs = funcType.getArguments();
		Function f = Utils.createFunction(name, address, false);
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
