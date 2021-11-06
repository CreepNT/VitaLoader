package vita.types;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.program.model.mem.MemoryAccessException;

import vita.misc.TypeHelper;
import vita.elf.VitaElfExtension.ProcessingContext;

public class SceModuleImports_3xx implements StructConverter {
	public short size;
	public short version;
	public short attribute;
	public short num_functions;
	public short num_vars;
	public short unk1;
	public long library_nid;
	public long library_name_ptr;
	public long func_nid_table;
	public long func_entry_table;
	public long var_nid_table;
	public long var_entry_table;
	private ProcessingContext _ctx;
	private Address _selfAddress;
	public static final int SIZE = 0x24;
	public static final String NAME = "SceModuleImports_3xx";
	
	public String _LibraryName;	//Parsed library name - not part of the struct itself

	public SceModuleImports_3xx(ProcessingContext ctx, Address moduleImportsAddr) 
			throws IOException, MemoryAccessException {
		BinaryReader reader = TypeHelper.getByteArrayBackedBinaryReader(ctx, moduleImportsAddr, SIZE);

		size = reader.readNextShort();
		version = reader.readNextShort();
		attribute = reader.readNextShort();
		num_functions = reader.readNextShort();
		num_vars = reader.readNextShort();
		unk1 = reader.readNextShort();
		library_nid = reader.readNextUnsignedInt();
		library_name_ptr = reader.readNextUnsignedInt();
		func_nid_table = reader.readNextUnsignedInt();
		func_entry_table = reader.readNextUnsignedInt();
		var_nid_table = reader.readNextUnsignedInt();
		var_entry_table = reader.readNextUnsignedInt();
		
		_ctx = ctx;
		_selfAddress = moduleImportsAddr;
		
		if (library_name_ptr != 0L) {
			BinaryReader libNameReader = TypeHelper.getMemoryBackedBinaryReader(ctx.memory,
					ctx.textBlock.getStart().getNewAddress(library_name_ptr));
			_LibraryName = libNameReader.readNextAsciiString();
		}
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}
	
	public void apply() throws Exception {
		StructureDataType dt = TypeHelper.createAndGetStructureDataType(NAME);
		dt.add(WORD, "size", "Size of this structure");
		dt.add(WORD, "version", null);
		dt.add(WORD, "attribute", null);
		dt.add(WORD, "num_functions", "Number of functions imported from this library");
		dt.add(WORD, "num_vars", "Number of variables imported from this library");
		dt.add(WORD, "unk", null);
		dt.add(DWORD, "library_nid", "Numeric ID of library");
		dt.add(new Pointer32DataType(StringDataType.dataType), "library_name", "Pointer to library name");
		dt.add(Pointer32DataType.dataType, "func_nid_table", "Pointer to functions NID table");
		dt.add(Pointer32DataType.dataType, "func_entry_table", "Pointer to functions entrypoints table");
		dt.add(Pointer32DataType.dataType, "var_nid_table", "Pointer to variables NID table");
		dt.add(Pointer32DataType.dataType, "var_entry_table", "Pointer to variables entry table");
		
		if (dt.getLength() != SIZE)
			System.err.println("Unexpected " + NAME + " data type size (" + dt.getLength() + " != expected " + SIZE + " !)");
		
		_ctx.api.clearListing(_selfAddress, _selfAddress.add(dt.getLength()));
		_ctx.api.createData(_selfAddress, dt);
		_ctx.api.createLabel(_selfAddress, _ctx.moduleName + "_SceModuleImports_" + _LibraryName, true);
	}
}
