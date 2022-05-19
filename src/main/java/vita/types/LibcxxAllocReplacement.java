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
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.FunctionDefinitionDataType;

import vita.misc.TypeManager;
import vita.misc.Utils;
import vita.elf.VitaElfExtension.ProcessingContext;

public class LibcxxAllocReplacement implements StructConverter {
	
	//regular new are defined as FUNCTION(...) throw(std::bad_alloc)
	//regular delete are defined as FUNCTION(...) throw()
	//nothrow versions of all function are defined as FUNCTION(..., const std::nothrow_t&) throw()
	public long size;
	public long unk4;
	public long user_new;
	public long user_new_nothrow;
	public long user_new_array;
	public long user_new_array_nothrow;
	public long user_delete;
	public long user_delete_nothrow;
	public long user_delete_array;
	public long user_delete_array_nothrow;
	private final ProcessingContext _ctx;
	private final Address _selfAddress;
	public static final int SIZE = 0x28;
	public static final String NAME = "SceLibstdcxxAllocReplacement";
	
	private static CategoryPath LIBCXX_REPLACEMENT_CATPATH = new CategoryPath(SceLibcParam_2xx.CATPATH, "LibcxxAllocReplacement");
	
	public LibcxxAllocReplacement(ProcessingContext ctx, Address libcxxAllocReplaceAddress, BinaryReader reader) throws IOException {
		size = reader.readNextUnsignedInt();
		unk4 = reader.readNextUnsignedInt();
		user_new = reader.readNextUnsignedInt();
		user_new_nothrow = reader.readNextUnsignedInt();
		user_new_array = reader.readNextUnsignedInt();
		user_new_array_nothrow = reader.readNextUnsignedInt();
		user_delete = reader.readNextUnsignedInt();
		user_delete_nothrow = reader.readNextUnsignedInt();
		user_delete_array = reader.readNextUnsignedInt();
		user_delete_array_nothrow = reader.readNextUnsignedInt();
		
		_ctx = ctx;
		_selfAddress = libcxxAllocReplaceAddress;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}

	
	public void apply() throws Exception {
		//Local declarations for convenience
		final DataType size_t = new TypedefDataType("size_t", UnsignedIntegerDataType.dataType);
		final DataType pVoid = TypeManager.PVOID;
		final DataType uint = TypeManager.u32;

		//Create function signatures
		FunctionDefinitionDataType F_user_new = fdef("user_new", pVoid, spdef("size", size_t));
		FunctionDefinitionDataType F_user_new_nothrow = fdef("user_new_nothrow", pVoid, pdef(new String[] {"size", "std_nothrow_t_reference"}, new DataType[] {size_t, pVoid}));
		FunctionDefinitionDataType F_user_new_array = fdef("user_new_array", pVoid, spdef("size", size_t));
		FunctionDefinitionDataType F_user_new_array_nothrow = fdef("user_new_array_nothrow", pVoid, pdef(new String[] {"size", "std_nothrow_t_reference"}, new DataType[] {size_t, pVoid}));
		FunctionDefinitionDataType F_user_delete = fdef("user_delete", VOID, spdef("ptr", pVoid));
		FunctionDefinitionDataType F_user_delete_nothrow = fdef("user_delete_nothrow", VOID, pdef(new String[]{"ptr", "std_nothrow_t_reference"}, new DataType[]{pVoid, pVoid}));
		FunctionDefinitionDataType F_user_delete_array = fdef("user_delete_array", VOID, spdef("ptr", pVoid));
		FunctionDefinitionDataType F_user_delete_array_nothrow = fdef("user_delete_array_nothrow", VOID, pdef(new String[]{"ptr", "std_nothrow_t_reference"}, new DataType[]{pVoid, pVoid}));
		
		//Create the structure itself
		StructureDataType libcxx_alloc_replace_struct = new StructureDataType(SceLibcParam_2xx.CATPATH, NAME, 0);
		libcxx_alloc_replace_struct.add(size_t, "size", "Size of this structure");
		libcxx_alloc_replace_struct.add(uint, "unk4", null);
		libcxx_alloc_replace_struct.add(new Pointer32DataType(F_user_new), "new", "operator new(std::size_t) throw(std::bad_alloc) replacement");
		libcxx_alloc_replace_struct.add(new Pointer32DataType(F_user_new_nothrow), "new_nothrow", "operator new(std::size_t, const std::nothrow_t&) throw() replacement");
		libcxx_alloc_replace_struct.add(new Pointer32DataType(F_user_new_array), "new_array", "operator new[](std::size_t) throw(std::bad_alloc) replacement");
		libcxx_alloc_replace_struct.add(new Pointer32DataType(F_user_new_array_nothrow), "new_array_nothrow", "operator new[](std::size_t, const std::nothrow_t&) throw() replacement");
		libcxx_alloc_replace_struct.add(new Pointer32DataType(F_user_delete), "delete", "operator delete(void*) throw() replacement");
		libcxx_alloc_replace_struct.add(new Pointer32DataType(F_user_delete_nothrow), "delete_nothrow", "operator delete(void*, const std::nothrow_t&) throw() replacement");
		libcxx_alloc_replace_struct.add(new Pointer32DataType(F_user_delete_array), "delete_array", "operator delete[](void*) throw() replacement");
		libcxx_alloc_replace_struct.add(new Pointer32DataType(F_user_delete_array_nothrow), "delete_array_nothrow", "operator delete[](void*, const std::nothrow_t&) throw() replacement");
		
		if (libcxx_alloc_replace_struct.getLength() != SIZE)
			System.err.println("Unexpected " + NAME + " data type size (" + libcxx_alloc_replace_struct.getLength() + " != expected " + SIZE + " !)");
		
		Utils.createDataInNamespace(_selfAddress, Utils.getModuleName(), NAME, libcxx_alloc_replace_struct);
		
		//Markup functions
		__markup_if_present(this.user_new, "user_new", F_user_new);
		__markup_if_present(this.user_new_nothrow, "user_new_nothrow", F_user_new);
		__markup_if_present(this.user_new_array, "user_new_array", F_user_new_array);
		__markup_if_present(this.user_new_array_nothrow, "user_new_array_nothrow", F_user_new_array_nothrow);
		__markup_if_present(this.user_delete, "user_delete", F_user_delete);
		__markup_if_present(this.user_delete_nothrow, "user_delete_nothrow", F_user_delete_nothrow);
		__markup_if_present(this.user_delete_array, "user_delete_array", F_user_delete_array);
		__markup_if_present(this.user_delete_array_nothrow, "user_delete_array_nothrow", F_user_delete_array_nothrow);
	}
	
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
		FunctionDefinitionDataType r = new FunctionDefinitionDataType(LIBCXX_REPLACEMENT_CATPATH, name);
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




























