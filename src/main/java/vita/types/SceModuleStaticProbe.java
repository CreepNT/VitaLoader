package vita.types;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.util.exception.DuplicateNameException;

import vita.misc.TypeHelper;
import vita.misc.Utils;
import vita.elf.VitaElfExtension.ProcessingContext;

public class SceModuleStaticProbe implements StructConverter {
	public long unk0;
	public String namePart1 = "";
	public String namePart2 = "";
	public long pFunc;
	public long pUnk10;
	public static final String STRUCTURE_NAME = "SceModuleStaticProbe";

	private ProcessingContext _ctx;
	private Address _selfAddress;
	
	public static DataType getDataType() {
		StructureDataType dt = TypeHelper.createAndGetStructureDataType(STRUCTURE_NAME);
		dt.add(Pointer32DataType.dataType, "unk0", "Pointer to ?uint32_t?/?structure?");
		dt.add(new Pointer32DataType(STRING), "pNamePart1", "Pointer to ?target object name?");
		dt.add(new Pointer32DataType(STRING), "pNamePart2", "Pointer to ?operation name?");
		dt.add(Pointer32DataType.dataType, "pFunc", "Pointer to some function");
		
		if (Utils.getModuleSDKVersion() > 0x00931000L) {
			dt.add(Pointer32DataType.dataType, "pUnk10", "Pointer to ?uint32_t?/?structure?");
		}
		
		return dt;
	}
	
	public SceModuleStaticProbe(ProcessingContext ctx, Address tableAddress) throws IOException {
		BinaryReader reader = TypeHelper.getMemoryBackedBinaryReader(_ctx.memory, tableAddress);
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
			BinaryReader libNameReader = TypeHelper.getMemoryBackedBinaryReader(ctx.memory,
					ctx.textBlock.getStart().getNewAddress(pNamePart1));
			namePart1 = libNameReader.readNextAsciiString();
		}
		if (pNamePart2 != 0L) {
			BinaryReader libNameReader = TypeHelper.getMemoryBackedBinaryReader(ctx.memory,
					ctx.textBlock.getStart().getNewAddress(pNamePart2));
			namePart2 = libNameReader.readNextAsciiString();
		}
		
		_ctx = ctx;
		_selfAddress = tableAddress;
	}
	

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return SceModuleStaticProbe.getDataType();
	}
	
	public void apply() throws Exception {
		DataType dt = this.toDataType();
		
		_ctx.api.clearListing(_selfAddress, _selfAddress.add(dt.getLength()));
		_ctx.api.createData(_selfAddress, dt);
		_ctx.api.createLabel(_selfAddress, namePart1 + namePart2 + "_StaticProbe", true);
	}
	
	public void process() throws ContextChangeException, AddressOutOfBoundsException {
		if (pFunc != 0L) {
			Function func = Utils.createFunction(namePart1 + namePart2, pFunc, false);
			func.setComment(String.format("Module static probe: %s%s", namePart1, namePart2));
		}
	}
}
