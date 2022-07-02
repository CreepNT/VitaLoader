package vita.types;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.data.Pointer32DataType;

import vita.misc.TypeManager;
import vita.misc.Utils;

public class SceModuleStaticProbe {
	public long unk0;
	public String namePart1 = "";
	public String namePart2 = "";
	public long pFunc;
	public long unk10;
	public long unk14;
	public long pProbeCreate;
	public long pProbeEnable;
	public long pProbeDisable;
	public long pProbeDestroy;
	public long unk28; //Up to FW 0.945.050
	public static final String STRUCTURE_NAME = "SceModuleStaticProbe";
	
	//Ideally a fw check should be enough, but the autodetect isn't very good and is pretty hard to improve.
	//Since unk28 is seemingly unused, it should be fine to not markup (at worse you can mark it up yourself)
	public static boolean ENABLE_UNK28_PARSING = false;

	private static StructureDataType DATATYPE = null;

	public static DataType toDataType() {
		if (DATATYPE == null) {
			DATATYPE = new StructureDataType(TypeManager.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);
			DATATYPE.add(Pointer32DataType.dataType, "unk0", "Pointer to ?uint32_t?/?structure?");
			DATATYPE.add(new Pointer32DataType(CharDataType.dataType), "pNamePart1", "Pointer to ?target object name?");
			DATATYPE.add(new Pointer32DataType(CharDataType.dataType), "pNamePart2", "Pointer to ?operation name?");
			DATATYPE.add(Pointer32DataType.dataType, "pFunc", "Pointer to some function");
			DATATYPE.add(Pointer32DataType.dataType, "unk10", "Pointer to a callback? (usually NULL)");
			DATATYPE.add(Pointer32DataType.dataType, "unk14", "Pointer to something? (usually 0)");
			DATATYPE.add(Pointer32DataType.dataType, "pProbeCreate", "Pointer to probe creation function");
			DATATYPE.add(Pointer32DataType.dataType, "pProbeEnable", "Pointer to probe enabling function");
			DATATYPE.add(Pointer32DataType.dataType, "pProbeDisable", "Pointer to probe disabling function");
			DATATYPE.add(Pointer32DataType.dataType, "pProbeDestroy", "Pointer to probe destruction function");
		
			if (Utils.getModuleSDKVersion() <= 0x00945050L && ENABLE_UNK28_PARSING) {
				DATATYPE.add(Pointer32DataType.dataType, "unk28", "Pointer to something? (usually 0)");
			}
		}
		return DATATYPE;
	}
	
	public SceModuleStaticProbe(Address tableAddress) throws Exception {
		BinaryReader reader = Utils.getMemoryReader(tableAddress);
		unk0 = reader.readNextUnsignedInt();
		long pNamePart1 = reader.readNextUnsignedInt();
		long pNamePart2 = reader.readNextUnsignedInt();
		
		pFunc = reader.readNextUnsignedInt();
		unk10 = reader.readNextUnsignedInt();
		unk14 = reader.readNextUnsignedInt();
		pProbeCreate = reader.readNextUnsignedInt();
		pProbeEnable = reader.readNextUnsignedInt();
		pProbeDisable = reader.readNextUnsignedInt();
		pProbeDestroy = reader.readNextUnsignedInt();
		
		if (Utils.getModuleSDKVersion() <= 0x00945050L && ENABLE_UNK28_PARSING) {
			unk28 = reader.readNextUnsignedInt();
		}
		
		if (pNamePart1 != 0L) {
			BinaryReader libNameReader = Utils.getMemoryReader(Utils.getProgramAddress(pNamePart1));
			namePart1 = libNameReader.readNextAsciiString();
		}
		if (pNamePart2 != 0L) {
			BinaryReader libNameReader = Utils.getMemoryReader(Utils.getProgramAddress(pNamePart2));
			namePart2 = libNameReader.readNextAsciiString();
		}
		
		Utils.createDataInNamespace(tableAddress, Utils.getModuleNamespace(), namePart1 + namePart2 + "_" + STRUCTURE_NAME, toDataType());
		
		markupFunc(pFunc, "probe_main_func");
		markupFunc(pProbeCreate, "ProbeCreate");
		markupFunc(pProbeEnable, "ProbeEnable");
		markupFunc(pProbeDisable, "ProbeDisable");
		markupFunc(pProbeDestroy, "ProbeDestroy");

	}

	private void markupFunc(long addr, String name) throws Exception {
		System.out.println(String.format("MARKUP %x %s", addr, name));
		if (addr != 0) {
			Function func =  Utils.createFunction(namePart1 + namePart2 + "_" + name, addr, false);
			func.setComment(String.format("Module static probe: %s%s | %s", namePart1, namePart2, name));
		}
	}
}
