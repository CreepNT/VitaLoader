package ghidra.app.util.opinion;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import utility.function.ExceptionalCallback;
import org.apache.commons.lang3.ClassUtils;
import org.apache.commons.lang3.reflect.MethodUtils;

public class DefaultElfProgramBuilder extends ElfProgramBuilder {

	protected static final String SEGMENT_NAME_PREFIX = "segment_";

	protected DefaultElfProgramBuilder(ElfHeader elf, Program program, List<Option> options,
			MessageLog log) {
		super(elf, program, options, log);
	}

	protected boolean shouldIncludeOtherBlocks() {
		List<Option> options = getField("options");
		return ElfLoaderOptionsFactory.includeOtherBlocks(options);
	}

	//////////////////////////////////////////////////////////////////////////////////////////
	//							PRIVATE METHOD DELEGATES									//
	//////////////////////////////////////////////////////////////////////////////////////////

	protected Address getSegmentLoadAddress(ElfProgramHeader elfProgramHeader) {
		return invoke("getSegmentLoadAddress", elfProgramHeader);
	}

	protected String getMessage(Exception e) {
		return invoke("getMessage", e);
	}

	protected String getSectionComment(long addr, long byteSize, int addressableUnitSize,
			String description, boolean loaded) {
		return invoke(
			"getSectionComment", addr, byteSize, addressableUnitSize, description, loaded);
	}


	@SuppressWarnings("unused")
	protected void processProgramHeaders(TaskMonitor monitor) throws CancelledException {
		invoke("processProgramHeaders", monitor);
	}

	@SuppressWarnings("unused")
	protected void addProgramProperties(TaskMonitor monitor) throws CancelledException {
		invoke("addProgramProperties", monitor);
	}

	protected void setImageBase() {
		invoke("setImageBase");
	}

	@SuppressWarnings("unused")
	protected void processSectionHeaders(TaskMonitor monitor) throws CancelledException {
		invoke("processSectionHeaders", monitor);
	}

	@SuppressWarnings("unused")
	protected void expandProgramHeaderBlocks(TaskMonitor monitor) throws CancelledException {
		invoke("expandProgramHeaderBlocks", monitor);
	}

	protected void joinProgramTreeFragments(Address block1End, Address block2Start) {
		invoke("joinProgramTreeFragments", block1End, block2Start);
	}

	protected void pruneDiscardableBlocks() {
		invoke("pruneDiscardableBlocks");
	}

	protected void markupElfHeader(TaskMonitor monitor) {
		invoke("markupElfHeader", monitor);
	}

	protected void markupProgramHeaders(TaskMonitor monitor) {
		invoke("markupProgramHeaders", monitor);
	}

	protected void markupSectionHeaders(TaskMonitor monitor) {
		invoke("markupSectionHeaders", monitor);
	}

	protected void markupDynamicTable(TaskMonitor monitor) {
		invoke("markupDynamicTable", monitor);
	}

	protected void markupInterpreter(TaskMonitor monitor) {
		invoke("markupInterpreter", monitor);
	}

	protected void processStringTables(TaskMonitor monitor) {
		invoke("processStringTables", monitor);
	}

	protected void processSymbolTables(TaskMonitor monitor) {
		invoke("processSymbolTables", monitor);
	}

	protected void processRelocations(TaskMonitor monitor) {
		invoke("processRelocations", monitor);
	}

	protected void processEntryPoints(TaskMonitor monitor) {
		invoke("processEntryPoints", monitor);
	}

	protected void processImports(TaskMonitor monitor) {
		invoke("processImports", monitor);
	}

	protected void markupHashTable(TaskMonitor monitor) {
		invoke("markupHashTable", monitor);
	}

	protected void markupGnuHashTable(TaskMonitor monitor) {
		invoke("markupGnuHashTable", monitor);
	}

	protected void processGNU(TaskMonitor monitor) {
		invoke("processGNU", monitor);
	}

	protected void processGNU_readOnly(TaskMonitor monitor) {
		invoke("processGNU_readOnly", monitor);
	}

	//////////////////////////////////////////////////////////////////////////////////////////
	//							PRIVATE FIELD DELEGATES										//
	//////////////////////////////////////////////////////////////////////////////////////////

	protected final HashMap<ElfSymbol, Address> getSymbolMap() {
		return getField("symbolMap");
	}

	protected final void setSymbolMap(HashMap<ElfSymbol, Address> symbolMap) {
		setField("symbolMap", symbolMap);
	}

	protected final Listing getListing() {
		return getField("listing");
	}

	protected final void setElfHeader(ElfHeader elf) {
		setField("elf", elf);
	}

	protected final void setLog(MessageLog log) {
		setField("log", log);
	}

	protected final List<Option> getOptions() {
		return getField("options");
	}

	protected final void setOptions(List<Option> options) {
		setField("options", options);
	}

	protected final Long getDataImageBase() {
		return getField("dataImageBase");
	}

	protected final void setDataImageBase(Long dataImageBase) {
		setField("dataImageBase", dataImageBase);
	}

	protected final FileBytes getFileBytes() {
		return getField("fileBytes");
	}

	protected final void setFileBytes(FileBytes bytes) {
		setField("fileBytes", bytes);
	}

	@SuppressWarnings("unchecked")
	private <R> R getField(String field) {
		return invoke(() -> {
			Field f = ElfProgramBuilder.class.getDeclaredField(field);
			f.setAccessible(true);
			R result = (R) f.get(this);
			f.setAccessible(false);
			return result;
		});
	}

	private <T> void setField(String field, T value) {
		invoke(() -> {
			Field f = ElfProgramBuilder.class.getDeclaredField(field);
			f.setAccessible(true);
			f.set(this, value);
			f.setAccessible(false);
		});
	}

	@SuppressWarnings("unchecked")
	private <R> R invoke(String method, Object... args) {
		return invoke(() -> {
			Class<?>[] types = ClassUtils.toClass(args);
			Method m = MethodUtils.getMatchingMethod(ElfProgramBuilder.class, method, types);
			m.setAccessible(true);
			return (R) m.invoke(this, args);
		});
	}

	private <R, E extends Exception> R invoke(ExceptionalSupplier<R, E> s) {
		try {
			return s.get();
		} catch (Exception e) {
			throw new AssertException(e);
		}
	}

	private static <E extends Exception> void invoke(ExceptionalCallback<E> c) {
		try {
			c.call();
		} catch (Exception e) {
			throw new AssertException(e);
		}
	}

	@FunctionalInterface
	private static interface ExceptionalSupplier<R, E extends Exception> {
		public R get() throws E;
	}
}