package vita.types;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.util.exception.DuplicateNameException;

import vita.misc.TypesManager;
import vita.elf.VitaElfExtension.ProcessingContext;

public class SceLibcParam_1xx implements StructConverter {
	public long size;
	public long unk4;
	public long heap_size;
	public long heap_size_default;
	public long heap_extended_alloc;
	public long heap_delayed_alloc;
	public long unk18;
	public long unk1C;
	public long malloc_replace;
	public long free_replace;
	public static final int SIZE = 0x28;
	public static final String NAME = "SceLibcParam_1xx";
	
	//TODO: I'm fairly certain some of those fields are ptr-to-struct, needs some RE
	//TODO: verify what malloc_replace and free_replace are (probably LibcReplace and LibcxxReplace)
	//TODO: refactor
	
	public SceLibcParam_1xx(BinaryReader reader) throws IOException {
		size = reader.readNextUnsignedInt();
		unk4 = reader.readNextUnsignedInt();
		heap_size = reader.readNextUnsignedInt();
		heap_size_default = reader.readNextUnsignedInt();
		heap_extended_alloc = reader.readNextUnsignedInt();
		heap_delayed_alloc = reader.readNextUnsignedInt();
		unk18 = reader.readNextUnsignedInt();
		unk1C = reader.readNextUnsignedInt();
		malloc_replace = reader.readNextUnsignedInt();
		free_replace = reader.readNextUnsignedInt();
	}
	
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}

	public void apply(ProcessingContext ctx, Address libcParamAddress, String moduleName) throws Exception {
		StructureDataType dt = TypesManager.createAndGetStructureDataType(NAME);
		dt.add(DWORD, "size", null);
		dt.add(DWORD, 4, "unk_0x4", null);
		dt.add(DWORD, "heap_size", null);
		dt.add(DWORD, "heap_size_default", null);
		dt.add(DWORD, "heap_extended_alloc", null);
		dt.add(DWORD, "heap_delayed_alloc", null);
		dt.add(DWORD, "unk_0x18", null);
		dt.add(DWORD, "unk_0x1C", null);
		dt.add(Pointer32DataType.dataType, "malloc_replace", null);		
		dt.add(Pointer32DataType.dataType, "free_replace", null);

		if (dt.getLength() != SIZE)
			System.err.println("Unexpected " + NAME + " data type size (" + dt.getLength() + " != expected " + SIZE + " !)");

		ctx.api.clearListing(libcParamAddress, libcParamAddress.add(dt.getLength()));
		ctx.api.createData(libcParamAddress, dt);
		ctx.api.createLabel(libcParamAddress, moduleName + "_SceLibcParam", true);
	}
}
