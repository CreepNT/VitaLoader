package vita.types;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.data.Pointer32DataType;

import vita.misc.TypeManager;
import vita.misc.Utils;

public class sdt_probedesc_t {
	public long sdpd_id;
	public String sdpd_provider;
	public String sdpd_name;
	public long sdpd_offset;
	public long sdpd_handler_fn;
	public long sdpd_private;
	public long sdpd_create_fn;
	public long sdpd_enable_fn;
	public long sdpd_disable_fn;
	public long sdpd_destroy_fn;
	public long unk28; //Up to FW 0.945.050
	public static final String STRUCTURE_NAME = "sdt_probedesc_t";
	
	//Ideally a fw check should be enough, but the autodetect isn't very good and is pretty hard to improve.
	//Since unk28 is seemingly unused, it should be fine to not markup (at worse you can mark it up yourself)
	public static boolean ENABLE_UNK28_PARSING = false;

	private static StructureDataType DATATYPE = null;

	public static DataType toDataType() {
		if (DATATYPE == null) {
			DATATYPE = new StructureDataType(TypeManager.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);
			
			ParameterDefinition[] helperFnArgs = new ParameterDefinitionImpl[1];
			helperFnArgs[0] = new ParameterDefinitionImpl("desc", new Pointer32DataType(DATATYPE), "");
			
			FunctionDefinitionDataType helperFn = new FunctionDefinitionDataType(TypeManager.SCE_TYPES_CATPATH ,"sdpd_helper_function");
			helperFn.setArguments(helperFnArgs);
			helperFn.setReturnType(VoidDataType.dataType);

			//This should be a union with multiple function pointers but varargs will do just as well
			FunctionDefinitionDataType handlerFn = new FunctionDefinitionDataType(TypeManager.SCE_TYPES_CATPATH, "sdpd_handler_t");
			handlerFn.setArguments(helperFnArgs);
			handlerFn.setReturnType(VoidDataType.dataType);
			handlerFn.setVarArgs(true);
			
			DataType pHelperFn = new Pointer32DataType(helperFn);
			DataType pHandlerFn = new Pointer32DataType(handlerFn);
			
			DATATYPE.add(new Pointer32DataType(UnsignedIntegerDataType.dataType), "sdpd_id", "Probe ID");
			DATATYPE.add(new Pointer32DataType(CharDataType.dataType), "sdpd_provider", "Name of provider");
			DATATYPE.add(new Pointer32DataType(CharDataType.dataType), "sdpd_name", "Name of probe");
			DATATYPE.add(Pointer32DataType.dataType, "sdpd_offset", "Instrumentation point (address)");
			DATATYPE.add(new Pointer32DataType(pHandlerFn), "sdpd_handler_fn", "Probe handler_fn function (NULL if disabled)");
			DATATYPE.add(TypeManager.PVOID, "sdpd_private", "Probe private data");
			DATATYPE.add(pHelperFn, "sdpd_create_fn", "Probe create helper function (NULL if unused)");
			DATATYPE.add(pHelperFn, "sdpd_enable_fn", "Probe enable helper function (NULL if unused)");
			DATATYPE.add(pHelperFn, "sdpd_disable_fn", "Probe disable helper function (NULL if unused)");
			DATATYPE.add(pHelperFn, "sdpd_destroy_fn", "Probe destroy helper function (NULL if unused)");
		
			if (Utils.getModuleSDKVersion() <= 0x00945050L && ENABLE_UNK28_PARSING) {
				DATATYPE.add(Pointer32DataType.dataType, "unk28", "Pointer to something? (usually 0)");
			}
		}
		return DATATYPE;
	}
	
	public sdt_probedesc_t(Address tableAddress) throws Exception {
		BinaryReader reader = Utils.getMemoryReader(tableAddress);
		sdpd_id = reader.readNextUnsignedInt();
		long pProviderName = reader.readNextUnsignedInt();
		long pProbeName = reader.readNextUnsignedInt();
		sdpd_offset = reader.readNextUnsignedInt();
		sdpd_handler_fn = reader.readNextUnsignedInt();
		sdpd_private = reader.readNextUnsignedInt();
		sdpd_create_fn = reader.readNextUnsignedInt();
		sdpd_enable_fn = reader.readNextUnsignedInt();
		sdpd_disable_fn = reader.readNextUnsignedInt();
		sdpd_destroy_fn = reader.readNextUnsignedInt();
		
		if (Utils.getModuleSDKVersion() <= 0x00945050L && ENABLE_UNK28_PARSING) {
			unk28 = reader.readNextUnsignedInt();
		}
		
		if (pProviderName != 0L) {
			BinaryReader libNameReader = Utils.getMemoryReader(Utils.getProgramAddress(pProviderName));
			sdpd_provider = libNameReader.readNextAsciiString();
		}
		if (pProbeName != 0L) {
			BinaryReader libNameReader = Utils.getMemoryReader(Utils.getProgramAddress(pProbeName));
			sdpd_name = libNameReader.readNextAsciiString();
		}
		
		Utils.createDataInNamespace(tableAddress, Utils.getModuleNamespace(), sdpd_provider + sdpd_name + "_probe_descriptor", toDataType());
		
		if (sdpd_offset != 0L) {
			Function func =  Utils.createFunction(sdpd_provider + sdpd_name + "_instrumentation_point", sdpd_offset);
			String comment = "Static DTrace probe\n";
			comment += "Provider name: " + sdpd_provider + "\n";
			comment += "Probe name: " + sdpd_name + "\n";
			comment += "Probe instrumentation point";
			
			func.setComment(comment);
		}
		
		markupHelper(sdpd_create_fn, "create");
		markupHelper(sdpd_enable_fn, "enable");
		markupHelper(sdpd_disable_fn, "disable");
		markupHelper(sdpd_destroy_fn, "destroy");
	}

	private void markupHelper(long addr, String name) throws Exception {
		if (addr != 0) {
			Function func =  Utils.createFunction(sdpd_provider + sdpd_name + "_" + name + "_fn", addr);
			String comment = "Static DTrace probe\n";
			comment += "Provider name: " + sdpd_provider + "\n";
			comment += "Probe name: " + sdpd_name + "\n";
			comment += "Probe " + name + " helper";
			
			func.setComment(comment);
		}
	}
}
