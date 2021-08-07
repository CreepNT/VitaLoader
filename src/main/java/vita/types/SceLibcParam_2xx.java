package vita.types;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.util.exception.DuplicateNameException;
import vita.elf.VitaElfExtension.ProcessingContext;
import vita.misc.TypesManager;

public class SceLibcParam_2xx implements StructConverter {
	public long size;
	public long unk4;
	public long heap_size;
	public long heap_size_default;
	public long heap_extended_alloc;
	public long heap_delayed_alloc;
	public long unk18;
	public long unk1C;
	public long libc_alloc_replacement;
	public long libcxx_alloc_replacement;
	public long unk28;
	public long unk2C;
	public long unk30;
	public long tls_alloc_replacement;
	public static final int SIZE = 0x38;
	public static final String NAME = "SceLibcParam_2xx";
	
	//TODO: more RE on the struct
	//TODO: refactor
	public SceLibcParam_2xx(BinaryReader reader) throws IOException {
		size = reader.readNextUnsignedInt();
		unk4 = reader.readNextUnsignedInt();
		heap_size = reader.readNextUnsignedInt();
		heap_size_default = reader.readNextUnsignedInt();
		heap_extended_alloc = reader.readNextUnsignedInt();
		heap_delayed_alloc = reader.readNextUnsignedInt();
		unk18 = reader.readNextUnsignedInt();
		unk1C = reader.readNextUnsignedInt();
		libc_alloc_replacement = reader.readNextUnsignedInt();
		libcxx_alloc_replacement = reader.readNextUnsignedInt();
		unk28 = reader.readNextUnsignedInt();
		unk2C = reader.readNextUnsignedInt();
		unk30 = reader.readNextUnsignedInt();
		tls_alloc_replacement = reader.readNextUnsignedInt();
	}
	
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}

	public void apply(ProcessingContext ctx, Address libcParamAddress, String moduleName) throws Exception {
		StructureDataType dt = TypesManager.createAndGetStructureDataType(NAME);
		dt.add(DWORD, "size", null);
		dt.add(STRING, 4, "unk4", null);
		dt.add(DWORD, "heap_size", null);
		dt.add(new PointerDataType(DWORD), "heap_size_default", "Pointer to the default heap size");
		dt.add(DWORD, "heap_extended_alloc", null);
		dt.add(DWORD, "heap_delayed_alloc", null);
		dt.add(DWORD, "unk18", null);
		dt.add(DWORD, "unk1C", null);
		dt.add(Pointer32DataType.dataType, "libc_alloc_replacement", "Pointer to replacement functions for Libc memory allocation functions");		
		dt.add(Pointer32DataType.dataType, "libcxx_alloc_replacement","Pointer to replacement functions for Libcxx (C++) memory allocation functions");
		dt.add(DWORD, "unk28", null);
		dt.add(DWORD, "unk2C", null);
		dt.add(DWORD, "unk30", null);
		dt.add(Pointer32DataType.dataType, "tls_alloc_replacement", "Pointer to replacement functions for TLS memory allocation functions");

		if (dt.getLength() != SIZE)
			System.err.println("Unexpected " + NAME + " data type size (" + dt.getLength() + " != expected " + SIZE + " !)");

		ctx.api.clearListing(libcParamAddress, libcParamAddress.add(dt.getLength()));
		ctx.api.createData(libcParamAddress, dt);
		ctx.api.createLabel(libcParamAddress, moduleName + "_SceLibcParam", true);
		
		
		if (this.heap_size_default != 0L) {
			ctx.api.createLabel(ctx.textBlock.getStart().getNewAddress(this.heap_size_default),
					moduleName + "_SceLibcDefaultHeapSize", true);
		}
		
		if (this.libc_alloc_replacement != 0L) {
			//Read size to make sure it's valid
			Address libcAllocReplacementAddress = ctx.textBlock.getStart().getNewAddress(libc_alloc_replacement);
			BinaryReader libcAllocReplacementReader = TypesManager.getByteArrayBackedBinaryReader(ctx, libcAllocReplacementAddress, LibcAllocReplacement.SIZE);
			int libcAllocReplacementSize = libcAllocReplacementReader.peekNextInt();//Use peek instead of read to keep index at 0 for struct creation
			
			switch (libcAllocReplacementSize) {
			//Apply struct if it is
			case LibcAllocReplacement.SIZE:
				new LibcAllocReplacement(libcAllocReplacementReader).apply(ctx, libcAllocReplacementAddress, moduleName);
				break;
			default:
				ctx.logger.appendMsg(String.format("Unknown " + LibcAllocReplacement.NAME + " size 0x%08X at address " + libcAllocReplacementAddress + " .", libcAllocReplacementSize));
				break;
			}
		}
		
		if (this.libcxx_alloc_replacement != 0L) {
			//Read size to make sure it's valid
			Address libcxxAllocReplacementAddress = ctx.textBlock.getStart().getNewAddress(libcxx_alloc_replacement);
			BinaryReader libcxxAllocReplacementReader = TypesManager.getByteArrayBackedBinaryReader(ctx, libcxxAllocReplacementAddress, LibcxxAllocReplacement.SIZE);
			int libcxxAllocReplacementSize = libcxxAllocReplacementReader.peekNextInt(); //Use peek instead of read to keep index at 0 for struct creation
			
			switch (libcxxAllocReplacementSize) {
			//Apply struct if it is
			case LibcxxAllocReplacement.SIZE:
				new LibcxxAllocReplacement(libcxxAllocReplacementReader).apply(ctx, libcxxAllocReplacementAddress, moduleName);
				break;
			default:
				ctx.logger.appendMsg(String.format("Unknown " + LibcxxAllocReplacement.NAME + " size 0x%08X at address " + libcxxAllocReplacementAddress + " .", libcxxAllocReplacementSize));
				break;
			}
		}
		if (this.tls_alloc_replacement != 0L) {
			//Read size to make sure it's valid
			Address tlsAllocReplacementAddress = ctx.textBlock.getStart().getNewAddress(tls_alloc_replacement);
			BinaryReader tlsAllocReplacementReader = TypesManager.getByteArrayBackedBinaryReader(ctx, tlsAllocReplacementAddress, TlsAllocReplacement.SIZE);
			int tlsAllocReplacementSize = tlsAllocReplacementReader.peekNextInt();//Use peek instead of read to keep index at 0 for struct creation
			
			switch (tlsAllocReplacementSize) {
			//Apply struct if it is
			case TlsAllocReplacement.SIZE:
				new TlsAllocReplacement(tlsAllocReplacementReader).apply(ctx, tlsAllocReplacementAddress, moduleName);
				break;
			default:
				ctx.logger.appendMsg(String.format("Unknown " + TlsAllocReplacement.NAME +  " size 0x%08X at address " + tlsAllocReplacementAddress + " .", tlsAllocReplacementSize));
				break;
			}
		}
		
	}
}

