package vita.misc;

import java.io.File;
import java.util.Map;
import java.util.HashMap;
import java.io.FileReader;
import java.io.FileNotFoundException;

import com.esotericsoftware.yamlbeans.YamlException;
import com.esotericsoftware.yamlbeans.YamlReader;

import resources.ResourceManager;
import vita.elf.VitaElfExtension.ProcessingContext;
import ghidra.framework.preferences.Preferences;
import docking.widgets.filechooser.GhidraFileChooser;

public class NIDDatabase {
	public static class NidDatabaseLibrary {
		public HashMap<Long, String> functions;
		public HashMap<Long, String> variables;

		public NidDatabaseLibrary() {
			functions = new HashMap<Long, String>();
			variables = new HashMap<Long, String>();
		}

		public boolean functionExists(long functionNid) {
			return functions.containsKey(functionNid);
		}

		public boolean variableExists(long variableNid) {
			return variables.containsKey(variableNid);
		}

		public void insertFunction(long functionNid, String name) {
			functions.put(functionNid, name);
		}

		public void insertVariable(long variableNid, String name) {
			variables.put(variableNid, name);
		}

		public String getFunctionName(long functionNid) {
			return functions.get(functionNid);
		}

		public String getVariableName(long variableNid) {
			return variables.get(variableNid);
		}
	}

	public HashMap<Long, NidDatabaseLibrary> libraries;
	
	private static final String INTERNAL_NIDS_DB_PATH = "databases\\NID_db.yml";
	private final ProcessingContext _ctx;
	
	public NIDDatabase(ProcessingContext ctx) {
		_ctx = ctx;
		libraries = new HashMap<Long, NidDatabaseLibrary>();
	}

	public boolean libraryExists(long nid) {
		return libraries.containsKey(nid);
	}
	
	public NidDatabaseLibrary getLibrary(long libraryNid) {
		return libraries.get(libraryNid);
	}

	public String getFunctionName(long libraryNid, long functionNid) {
		NidDatabaseLibrary library = getLibrary(libraryNid);
		if (library == null)
			return null;
		return library.getFunctionName(functionNid);
	}

	public String getVariableName(long libraryNid, long variableNid) {
		NidDatabaseLibrary library = getLibrary(libraryNid);
		if (library == null)
			return null;
		return library.getVariableName(variableNid);
	}

	public static class YamlNidDatabaseLibrary {
		public Long nid;
		public Boolean kernel;
		public Map<String, Long> functions;
		public Map<String, Long> variables;
	}

	public static class YamlNidDatabaseModule {
		public Long nid;
		public Map<String, YamlNidDatabaseLibrary> libraries;
	}

	public static class YamlNidDatabase {
		public int version;
		public String firmware;
		public Map<String, YamlNidDatabaseModule> modules;
	}

	private void insertLibrary(long libraryNid, NidDatabaseLibrary library) {
		libraries.put(libraryNid, library);
	}
	
	private void populateNidDatabaseFromYaml(YamlNidDatabase raw) {
		for (Map.Entry<String, YamlNidDatabaseModule> moduleIt: raw.modules.entrySet()) {
			YamlNidDatabaseModule moduleRaw = moduleIt.getValue();
			for (Map.Entry<String, YamlNidDatabaseLibrary> libraryIt: moduleRaw.libraries.entrySet()) {
				YamlNidDatabaseLibrary libraryRaw = libraryIt.getValue();
				NIDDatabase.NidDatabaseLibrary library = new NIDDatabase.NidDatabaseLibrary();
	
				for (Map.Entry<String, Long> functionIt: libraryRaw.functions.entrySet())
					library.insertFunction(functionIt.getValue(), functionIt.getKey());
	
				if (libraryRaw.variables != null)
					for (Map.Entry<String, Long> variableIt: libraryRaw.variables.entrySet())
						library.insertVariable(variableIt.getValue(), variableIt.getKey());
	
				insertLibrary(libraryRaw.nid, library);
			}
		}
	}

	public void populate(boolean promptForCustomDB) {
		File dbFile = null;
		
		if (promptForCustomDB) {
			GhidraFileChooser fileChooser = new GhidraFileChooser(null);
			String lastDir = Preferences.getProperty(Preferences.LAST_IMPORT_DIRECTORY);
			if (lastDir != null)
				fileChooser.setCurrentDirectory(new File(lastDir));
			fileChooser.setTitle("Choose NID database YML");
			fileChooser.setApproveButtonText("Parse selected file");
			fileChooser.rescanCurrentDirectory();
			dbFile = fileChooser.getSelectedFile();
		}

		//User-provided database loading failed, fallback to internal database
		if (dbFile == null) {
			dbFile = ResourceManager.getResourceFile(INTERNAL_NIDS_DB_PATH);
		}
		
		//Abort loading if we have no database
		if (dbFile == null) {
			return;
		}

		/* Load NID database */
		try {
			YamlReader yamlReader = new YamlReader(new FileReader(dbFile));
			YamlNidDatabase dbRaw = yamlReader.read(YamlNidDatabase.class);
			populateNidDatabaseFromYaml(dbRaw);
		} catch (YamlException | FileNotFoundException e) {
			_ctx.logger.appendMsg("Failed to load NIDs database due to the following exception:");
			_ctx.logger.appendException(e);
		}
	}
	
}
