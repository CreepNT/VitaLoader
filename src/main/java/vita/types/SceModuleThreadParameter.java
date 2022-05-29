package vita.types;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;


import vita.misc.TypeManager;
import vita.misc.Utils;

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
	
	public SceModuleThreadParameter(Address address, ModuleThreadParameterType parameterType) throws Exception {
		String epName = "";
		switch (parameterType) {
		case MODULE_START_PARAMETER:
			epName = "module_start";
			break;
		case MODULE_STOP_PARAMETER:
			epName = "module_stop";
			break;
		}
		
		BinaryReader reader = Utils.getMemoryReader(address);
		numParams = reader.readNextUnsignedInt();
		initPriority = reader.readNextInt();
		stackSize = reader.readNextUnsignedInt();
		attr = reader.readNextUnsignedInt();
		cpuAffinityMask = reader.readNextInt();
		
		Utils.createDataInNamespace(address, Utils.getModuleNamespace(), epName + "_thread_parameter", toDataType());
	}
	
	private static StructureDataType DATATYPE = null;	
	public static DataType toDataType() {
		if (DATATYPE == null) {
			final DataType SceInt32 = TypeManager.getDataType("SceInt32");
			final DataType SceSize = TypeManager.getDataType("SceSize");
			
			DATATYPE = new StructureDataType(TypeManager.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);
			DATATYPE.setDescription("Parameters used for creation of threads that run the module's entrypoints");
			DATATYPE.add(SceSize, "numParams", "Number of parameters in this structure (must be 4)");
			DATATYPE.add(SceInt32, "initPriority", "Initial priority of the entrypoint thread");
			DATATYPE.add(SceSize, "stackSize", "Size of the entrypoint thread's stack, in bytes");
			DATATYPE.add(TypeManager.getDataType("SceUInt32"), "attr", "Attributes - always ignored (replaced by 0x80008000)");
			DATATYPE.add(SceInt32, "cpuAffinityMask", "Affinity mask of the entrypoint thread");
		}
		
		return DATATYPE;
	}
}
