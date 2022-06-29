package vita.misc;

import java.io.File;
import java.util.Map;
import java.util.HashMap;
import java.io.FileReader;
import java.io.IOException;
import java.io.FileNotFoundException;

import com.esotericsoftware.yamlbeans.YamlException;
import com.esotericsoftware.yamlbeans.YamlReader;

import vita.elf.VitaElfExtension.ProcessingContext;
import ghidra.framework.Application;
import ghidra.framework.preferences.Preferences;
import docking.widgets.filechooser.GhidraFileChooser;
import generic.jar.ResourceFile;

public class DatabaseBroker {
	private static class LibraryNIDDatabase {
		public HashMap<Long, String> functions;
		public HashMap<Long, String> variables;

		public LibraryNIDDatabase() {
			functions = new HashMap<Long, String>();
			variables = new HashMap<Long, String>();
		}

		/*
		public boolean functionExists(long functionNid) {
			return functions.containsKey(functionNid);
		}

		public boolean variableExists(long variableNid) {
			return variables.containsKey(variableNid);
		}
		*/

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
	
	private HashMap<String, LibraryNIDDatabase> libraryNameToDatabaseMap = new HashMap<String, LibraryNIDDatabase>();
	private HashMap<Long, LibraryNIDDatabase> libraryNIDToDatabaseMap = new HashMap<Long, LibraryNIDDatabase>();
	private HashMap<String, String> libraryToModuleNameMap = new HashMap<String, String>();

	private static final String INTERNAL_NIDS_DB_PATH = "databases\\NID_db.yml";
	private static final String MODULE_NAME_TO_FILE_NAME_DB_PATH = "databases\\modfilename_db.yml";
	private final ProcessingContext _ctx;
	
	public DatabaseBroker(ProcessingContext ctx) {
		_ctx = ctx;
	}

	/*
	public boolean libraryExists(long nid) {
		return libraries.containsKey(nid);
	}
	
	public NidDatabaseLibrary getLibrary(long libraryNid) {
		return libraries.get(libraryNid);
	}
	*/

	private LibraryNIDDatabase _getLibrary(String libraryName, long libraryNid) {
		LibraryNIDDatabase lib = null;
		
		//Match by NID first - this allows the same library to be present multiple times in the same file if NID changed
		lib = libraryNIDToDatabaseMap.get(libraryNid);
		if (lib != null) {
			return lib;
		}
		
		//Then match by name if not found (or NID isn't valid like in 0.931 modules)
		lib = libraryNameToDatabaseMap.get(libraryName);
		
		return lib;
	}
	
	//Replaces hardcoded names in NameUtil.java
	//Only downside is that conflicting libraries (e.g. SceCamera can map to either SceCamera or SceCameraDummy) will
	//now default to the farthest in database?
	public String getModuleNameForLibrary(String libraryName) {
		return libraryToModuleNameMap.get(libraryName);
	}
	
	public String getFunctionName(String libraryName, long libraryNid, long functionNid) {
		LibraryNIDDatabase lib = _getLibrary(libraryName, libraryNid);
		return (lib == null) ? null : lib.getFunctionName(functionNid);
	}
	
	public String getVariableName(String libraryName, long libraryNid, long variableNid) {
		LibraryNIDDatabase lib = _getLibrary(libraryName, libraryNid);
		return (lib == null) ? null : lib.getVariableName(variableNid);
	}



	/* Glue for Yaml loader */
	public static class YamlNidDatabaseLibrary {
		public Long nid;
		public Boolean kernel;
		public Map<String, Long> functions;
		public Map<String, Long> variables;
	}

	public static class YamlNidDatabaseModule {
		public Long nid;
		public Long fingerprint;
		public Map<String, YamlNidDatabaseLibrary> libraries;
	}

	public static class YamlNidDatabase {
		public int version;
		public String firmware;
		public Map<String, YamlNidDatabaseModule> modules;
	}

	//TODO: pass a File instead
	//TODO: pass a boolean createStringToNIDmap
	public void populate(boolean promptForCustomDB) {
		boolean createStringToNIDmap = true;
		
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
			try {
				ResourceFile rf = Application.getModuleDataFile(INTERNAL_NIDS_DB_PATH);
				System.err.println("Internal NID db path:" + rf.getAbsolutePath() + " canonical: " + rf.getCanonicalPath());
				dbFile = new File(rf.toURI());
			} catch (IOException e) {
				System.err.println("FileNotFoundException getting internal database: " + e);
			}
		}
		
		//Abort loading if we have no database
		if (dbFile == null) {
			return;
		}

		/* Load NID database */
		try {
			YamlReader yamlReader = new YamlReader(new FileReader(dbFile));
			YamlNidDatabase databaseObject = yamlReader.read(YamlNidDatabase.class);
			
			for (Map.Entry<String, YamlNidDatabaseModule> moduleIt: databaseObject.modules.entrySet()) {
				YamlNidDatabaseModule module = moduleIt.getValue();
				String moduleName = moduleIt.getKey();
				
				for (Map.Entry<String, YamlNidDatabaseLibrary> libraryIt: module.libraries.entrySet()) {
					YamlNidDatabaseLibrary library = libraryIt.getValue();
					String libraryName = libraryIt.getKey();
					
					libraryToModuleNameMap.put(libraryName, moduleName);
					
					DatabaseBroker.LibraryNIDDatabase DBLibrary = new DatabaseBroker.LibraryNIDDatabase();
					
					if (library.functions != null) {
						for (Map.Entry<String, Long> functionIt: library.functions.entrySet())
							DBLibrary.insertFunction(functionIt.getValue(), functionIt.getKey());
					}
					
					if (library.variables != null) {
						for (Map.Entry<String, Long> variableIt: library.variables.entrySet())
							DBLibrary.insertVariable(variableIt.getValue(), variableIt.getKey());
					}
					
					if (library.nid != null) {
						libraryNIDToDatabaseMap.put(library.nid, DBLibrary);
					}
					if (createStringToNIDmap) {
						libraryNameToDatabaseMap.put(libraryName, DBLibrary);
					}
				}
			}
		} catch (YamlException | FileNotFoundException e) {
			_ctx.logger.appendMsg("Failed to load NIDs database due to the following exception:");
			_ctx.logger.appendException(e);
		}
	}
	
}
