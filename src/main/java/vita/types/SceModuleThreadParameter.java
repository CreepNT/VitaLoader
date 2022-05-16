package vita.types;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import vita.elf.VitaElfExtension.ProcessingContext;
import vita.misc.TypeHelper;

public class SceModuleThreadParameter {
	public enum ModuleThreadParameterType {
		MODULE_START_PARAMETER,
		MODULE_STOP_PARAMETER
	}
	
	public long numParams;
	public long initPriority;
	public long stackSize;
	public long attr;
	public long cpuAffinityMask;
	
	public final static String STRUCTURE_NAME = "SceModuleThreadParameter";
	
	private final ProcessingContext _ctx;
	private final Address _selfAddress;
	private final ModuleThreadParameterType _parameterType;
	

	
	public SceModuleThreadParameter(ProcessingContext ctx, Address structAddr, ModuleThreadParameterType parameterType) {
		_ctx = ctx;
		_selfAddress = structAddr;
		_parameterType = parameterType; 
	}
	
	public static DataType dataType() {
		StructureDataType dt = TypeHelper.createAndGetStructureDataType(TypeHelper.SCE_TYPES_CATPATH, STRUCTURE_NAME);
		dt.setDescription("Parameters used for creation of threads that run the module's entrypoints");
		dt.add(TypeHelper.u32, "numParams", "Number of parameters in this structure (must be 4)");
		dt.add(TypeHelper.s32, "initPriority", "Initial priority of the entrypoint thread");
		dt.add(TypeHelper.u32, "stackSize", "Size of the entrypoint thread's stack, in bytes");
		dt.add(TypeHelper.u32, "attr", "Attributes - always ignored (replaced by 0x80008000)");
		dt.add(TypeHelper.s32, "cpuAffinityMask", "Affinity mask of the entrypoint thread");
		return dt;
	}
	
	public void apply() throws Exception {
		String epName = "";
		switch (_parameterType) {
		case MODULE_START_PARAMETER:
			epName = "module_start";
			break;
		case MODULE_STOP_PARAMETER:
			epName = "module_stop";
			break;
		}
		
		
		DataType dt = SceModuleThreadParameter.dataType();
		_ctx.api.clearListing(_selfAddress, _selfAddress.add(dt.getLength()));
		_ctx.api.createData(_selfAddress, dt);
		_ctx.api.createLabel(_selfAddress, epName + "_thread_parameter", true);
	}

}
