package vita.types;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.program.model.mem.MemoryAccessException;

import vita.misc.TypeHelper;
import vita.elf.VitaElfExtension.ProcessingContext;

//Bad name
//TODO fixme
public class SceProcessmgrProcFuncExport implements StructConverter {
	public long unk0;
	public String namePart1 = "";
	public String namePart2 = "";
	public long pFunc;
	public long pUnk10;
	public long unk14;
	public long unk18;
	public long unk1C;
	public long unk20;
	public long unk24;
	public static final int SIZE = 0x14; //In 0.931, size is 0x10 -- in 3.65, it *could* be 0x28, but seems to be 0x14 - all fields past that are zeroes
	public static final String NAME = "SceProcessmgrProcFuncExport";

	private ProcessingContext _ctx;
	private Address _selfAddress;
	private final boolean isThumb;
	
	public SceProcessmgrProcFuncExport(ProcessingContext ctx, Address tableAddress) throws IOException, MemoryAccessException {
		BinaryReader reader = TypeHelper.getByteArrayBackedBinaryReader(ctx, tableAddress, SIZE);
		unk0 = reader.readNextUnsignedInt();
		long pNamePart1 = reader.readNextUnsignedInt();
		long pNamePart2 = reader.readNextUnsignedInt();
		
		long funcPtr = reader.readNextUnsignedInt();
		isThumb = (funcPtr & 1L) != 0;
		pFunc = funcPtr & ~1L; //Clear LSB because Ghidra expects functions to be 2-byte aligned
		pUnk10 = reader.readNextUnsignedInt();
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
		return StructConverterUtil.toDataType(this);
	}
	
	public static DataType getDataType() {
		StructureDataType dt = TypeHelper.createAndGetStructureDataType(NAME);
		dt.add(Pointer32DataType.dataType, "unk0", "Pointer to ?uint32_t?/?structure?");
		dt.add(new Pointer32DataType(STRING), "pNamePart1", "Pointer to ?target object name?");
		dt.add(new Pointer32DataType(STRING), "pNamePart2", "Pointer to ?operation name?");
		dt.add(Pointer32DataType.dataType, "pFunc", "Pointer to some function");
		dt.add(Pointer32DataType.dataType, "pUnk10", "Pointer to ?uint32_t?/?structure? -- not present on 0.931");
		/*dt.add(TypeHelper.u32, "unk14", null);
		dt.add(TypeHelper.u32, "unk18", null);
		dt.add(TypeHelper.u32, "unk1C", null);
		dt.add(TypeHelper.u32, "unk20", null);
		dt.add(TypeHelper.u32, "unk24", null);*/
		
		if (dt.getLength() != SIZE)
			System.err.println("Unexpected " + NAME + " data type size (" + dt.getLength() + " != expected " + SIZE + " !)");
	
		return dt;
	}
	
	public void apply() throws Exception {
		DataType dt = getDataType();
		
		_ctx.api.clearListing(_selfAddress, _selfAddress.add(dt.getLength()));
		_ctx.api.createData(_selfAddress, dt);
		_ctx.api.createLabel(_selfAddress, namePart1 + namePart2 + "_table", true);
	}
	
	public void process() throws ContextChangeException, AddressOutOfBoundsException {
		Address funcAddr = _ctx.textStart.getNewAddress(pFunc);
		Function func = _ctx.api.createFunction(funcAddr, namePart1 + namePart2);
		func.setComment(String.format("NONAME variable export 0x%X: %s%s", 0x8CE938B1, namePart1, namePart2));

		if (isThumb) {
			_ctx.progContext.setRegisterValue(funcAddr, funcAddr.add(2), _ctx.TModeForThumb);
		} else {
			_ctx.progContext.setRegisterValue(funcAddr, funcAddr.add(4), _ctx.TModeForARM);
		}
	}
}
