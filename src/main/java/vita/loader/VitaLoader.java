/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package vita.loader;

import java.io.IOException;
import java.util.*;

import generic.continues.GenericFactory;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;


import vita.elf.VitaElfHeader;
import vita.elf.VitaElfProgramBuilder;

/**
 * Reimplements the ElfLoader methods to use Vita-specific types (also inherited from ElfXXX objects).
 */
public class VitaLoader extends ElfLoader {
	//Language for PS Vita ELFs : ARMv7 Little-endian w/ default compiler
	private static final LanguageCompilerSpecPair LANGUAGE =
			new LanguageCompilerSpecPair("ARM:LE:32:v7", "default");
	
	@Override
	public String getName() { return "PS Vita ELF";	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		//Get ELF header
		VitaElfHeader header = null;
		try {
			header = getElfHeader(provider);
		} catch (ElfException e) {
			return Collections.emptyList();
		}
		
		//Verify e_machine and e_type are expected values
		short type = header.e_type();
		short machine = header.e_machine();
		
		if (machine != VitaElfHeader.ARM_MACHINE_TYPE)
			return Collections.emptyList();
		
		switch (type) {
		case VitaElfHeader.ET_SCE_EXEC:
		case VitaElfHeader.ET_SCE_RELEXEC:
			List<LoadSpec> loadSpecs = new ArrayList<>();
			loadSpecs.add(new LoadSpec(this, header.findImageBase(), LANGUAGE, true));
			return loadSpecs;
		default:
			return Collections.emptyList();
		}
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		try {
			GenericFactory factory = MessageLogContinuesFactory.create(log);
			VitaElfHeader elf = VitaElfHeader.createElfHeader(factory, provider);
			VitaElfProgramBuilder.loadElf(elf, program, options, log, monitor);
		}
		catch (ElfException e) {
			throw new IOException(e.getMessage());
		}
	}

	public static String USE_CUSTOM_NIDS_DATABASE_OPTNAME = "Use User-Provided NIDs Database";
	public static String USE_CUSTOM_TYPES_DATABASE_OPTNAME = "Import User-Provided Types Database";
	
	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		
		list.add(new Option(USE_CUSTOM_NIDS_DATABASE_OPTNAME, true));
		//list.add(new Option(USE_CUSTOM_TYPES_DATABASE_OPTNAME, false)); //Types database code is just trash, don't allow user to use it

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		for (Option option : options) {
			String name = option.getName();
			if (name.equals(USE_CUSTOM_NIDS_DATABASE_OPTNAME) && !Boolean.class.isAssignableFrom(option.getValueClass())) {
				return "Invalid type for option: " + name + " - " + option.getValueClass();
			}
			if (name.equals(USE_CUSTOM_TYPES_DATABASE_OPTNAME) && !Boolean.class.isAssignableFrom(option.getValueClass())) {
				return "Invalid type for option: " + name + " - " + option.getValueClass();
			}
		}

		return super.validateOptions(provider, loadSpec, options, program);
	}
	
///////////////////
//Private methods//
///////////////////
	private static VitaElfHeader getElfHeader(ByteProvider provider) throws ElfException {
		return VitaElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, provider);
	}
}
