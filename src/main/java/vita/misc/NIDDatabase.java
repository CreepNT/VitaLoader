package vita.misc;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;

import com.esotericsoftware.yamlbeans.YamlException;
import com.esotericsoftware.yamlbeans.YamlReader;

import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.framework.preferences.Preferences;

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
	
	public static enum DatabaseType {
			DATABASE_NONE,
			DATABASE_INTERNAL,
			DATABASE_USER_PROVIDED
	}
	
	private static NIDDatabase INSTANCE = null;
	private static DatabaseType databaseType = DatabaseType.DATABASE_NONE;
	
	private NIDDatabase() {
		libraries = new HashMap<Long, NidDatabaseLibrary>();
	}
	
	public static NIDDatabase getInstance() {
		if (INSTANCE == null)
			INSTANCE = new NIDDatabase();
		return INSTANCE;
	}

	public static DatabaseType getDatabaseType() {
		return databaseType;
	}
	
	public static boolean libraryExists(long nid) {
		if (databaseType == DatabaseType.DATABASE_NONE)
			return false;
		return getInstance().libraries.containsKey(nid);
	}
	
	public static NidDatabaseLibrary getLibrary(long libraryNid) {
		if (databaseType == DatabaseType.DATABASE_NONE)
			return null;
		return getInstance().libraries.get(libraryNid);
	}

	public static String getFunctionName(long libraryNid, long functionNid) {
		NidDatabaseLibrary library = getLibrary(libraryNid);
		if (library == null)
			return null;
		return library.getFunctionName(functionNid);
	}

	public static String getVariableName(long libraryNid, long variableNid) {
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
	
	private static void populateNidDatabaseFromYaml(YamlNidDatabase raw) {
		NIDDatabase db = getInstance();
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
	
				db.insertLibrary(libraryRaw.nid, library);
			}
		}
	}

	@SuppressWarnings("unused")
	public static void populateInternalDatabase(boolean promptForCustomDB) throws FileNotFoundException, YamlException {
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
			databaseType = DatabaseType.DATABASE_USER_PROVIDED;
		}

		//User-provided database loading failed, fallback to internal database
		if (dbFile == null) {
			databaseType = DatabaseType.DATABASE_INTERNAL;
			//TODO: Try to load internal database
			
			//Internal database loading also failed, update state as such and abort processing
			if (dbFile == null) {
				databaseType = DatabaseType.DATABASE_NONE;
				return;
			}
			
		}

		/* Load NID database */
		YamlReader yamlReader = new YamlReader(new FileReader(dbFile));
		YamlNidDatabase dbRaw = yamlReader.read(YamlNidDatabase.class);
		populateNidDatabaseFromYaml(dbRaw);
		
	}
	
}