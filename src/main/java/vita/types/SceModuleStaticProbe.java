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
	public long pUnk10;
	public static final String STRUCTURE_NAME = "SceModuleStaticProbe";
	
	public static DataType toDataType() {
		StructureDataType dt = new StructureDataType(TypeManager.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);
		dt.add(Pointer32DataType.dataType, "unk0", "Pointer to ?uint32_t?/?structure?");
		dt.add(new Pointer32DataType(CharDataType.dataType), "pNamePart1", "Pointer to ?target object name?");
		dt.add(new Pointer32DataType(CharDataType.dataType), "pNamePart2", "Pointer to ?operation name?");
		dt.add(Pointer32DataType.dataType, "pFunc", "Pointer to some function");
		
		if (Utils.getModuleSDKVersion() > 0x00931000L) {
			dt.add(Pointer32DataType.dataType, "pUnk10", "Pointer to ?uint32_t?/?structure?");
		}
		
		return dt;
	}
	
	public SceModuleStaticProbe(Address tableAddress) throws Exception {
		BinaryReader reader = Utils.getMemoryReader(tableAddress);
		unk0 = reader.readNextUnsignedInt();
		long pNamePart1 = reader.readNextUnsignedInt();
		long pNamePart2 = reader.readNextUnsignedInt();
		
		pFunc = reader.readNextUnsignedInt();
		
		if (Utils.getModuleSDKVersion() > 0x00931000L) {
			pUnk10 = reader.readNextUnsignedInt();
		}
		
		/*unk14 = reader.readNextUnsignedInt();
		unk18 = reader.readNextUnsignedInt();
		unk1C = reader.readNextUnsignedInt();
		unk20 = reader.readNextUnsignedInt();
		unk24 = reader.readNextUnsignedInt();*/
		
		if (pNamePart1 != 0L) {
			BinaryReader libNameReader = Utils.getMemoryReader(Utils.getProgramAddress(pNamePart1));
			namePart1 = libNameReader.readNextAsciiString();
		}
		if (pNamePart2 != 0L) {
			BinaryReader libNameReader = Utils.getMemoryReader(Utils.getProgramAddress(pNamePart2));
			namePart2 = libNameReader.readNextAsciiString();
		}
		
		Utils.createDataInNamespace(tableAddress, Utils.getModuleNamespace(), namePart1 + namePart2 + "_" + STRUCTURE_NAME, toDataType());
		
		if (pFunc != 0L) {
			Function func = Utils.createFunction(namePart1 + namePart2, pFunc, false);
			func.setComment(String.format("Module static probe: %s%s", namePart1, namePart2));
		}
	}
}
