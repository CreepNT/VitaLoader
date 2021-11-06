package vita.misc;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.json.JSONException;
import org.json.JSONObject;

import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.util.bin.StructConverter;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.util.filechooser.ExtensionFileFilter;
import resources.ResourceManager;
import vita.elf.VitaElfExtension.ProcessingContext;

public class TypeDatabase {
	//Relative path in resources directory to the types database file
	private final static String TYPES_DB_PATH = "databases\types.json";
	private final static Map<String, DataType> PRIMITIVE_TYPES_MAP = Map.ofEntries(
			Map.entry("void", StructConverter.VOID),
			Map.entry("u64", TypeHelper.u64),
			Map.entry("s64", TypeHelper.s64),
			Map.entry("u32", TypeHelper.u32),
			Map.entry("s32", TypeHelper.s32),
			Map.entry("u16", TypeHelper.u16),
			Map.entry("s16", TypeHelper.s16),
			Map.entry("u8", TypeHelper.u8),
			Map.entry("s8", TypeHelper.s8),
			Map.entry("float", TypeHelper.f32),
			Map.entry("f32", TypeHelper.f32),
			Map.entry("double", TypeHelper.f64),
			Map.entry("f64",TypeHelper.f64),
			Map.entry("size_t", TypeHelper.size_t)
	);
	private final static CategoryPath TYPES_DB_CATEGORY = TypeHelper.TYPES_DB_CATPATH;
	private static final List<Character> specialCTokens = new ArrayList<>(Arrays.asList('*', '[', ']', '(', ')'));
	
	private final ProcessingContext _ctx;
		
	public TypeDatabase(ProcessingContext ctx) {
		this._ctx = ctx;
	}
		
	/**
	 * Adds a majority of the types from the <scetypes.h> header into the DataTypeManager
	 * of the ProcessingContext used to initialize this Database. Types will be stored
	 * under the SCE_TYPES_CATPATH category.
	 */
	public void addSceTypes() {
		this.addSceTypes(TypeHelper.SCE_TYPES_CATPATH);
	}

	/**
	 * Adds a majority of the types from the <scetypes.h> header into the DataTypeManager
	 * of the ProcessingContext used to initialize this Database. Types will be stored
	 * under the provided category.
	 */
	public void addSceTypes(CategoryPath destinationCategory) {
		Map.ofEntries(
			Map.entry("SceChar8", 		TypeHelper.s8),
			Map.entry("SceUChar8", 		TypeHelper.u8),
			Map.entry("SceInt8", 		TypeHelper.s8),
			Map.entry("SceUInt8", 		TypeHelper.u8),
			Map.entry("SceShort16", 	TypeHelper.s16),
			Map.entry("SceUShort16", 	TypeHelper.u16),
			Map.entry("SceInt16", 		TypeHelper.s16),
			Map.entry("SceUInt16", 		TypeHelper.u16),
			Map.entry("SceInt32", 		TypeHelper.s32),
			Map.entry("SceUInt32", 		TypeHelper.u32),
			Map.entry("SceInt", 		TypeHelper.s32),
			Map.entry("SceUInt", 		TypeHelper.u32),
			Map.entry("SceLong", 		TypeHelper.s32),
			Map.entry("SceULong", 		TypeHelper.u32),
			Map.entry("SceInt64", 		TypeHelper.s64),
			Map.entry("SceUInt64", 		TypeHelper.u64),
			Map.entry("SceLong64", 		TypeHelper.s64),
			Map.entry("SceULong64", 	TypeHelper.u64),
			Map.entry("SceFloat", 		TypeHelper.f32),
			Map.entry("SceFloat32", 	TypeHelper.f32),
			Map.entry("SceDouble", 		TypeHelper.f64),
			Map.entry("SceDouble64", 	TypeHelper.f64),
			Map.entry("SceSByte",		TypeHelper.s8),
			Map.entry("SceSByte8",		TypeHelper.s8),
			Map.entry("SceByte",		TypeHelper.u8),
			Map.entry("SceByte8",		TypeHelper.u8),
			Map.entry("SceWChar16",		TypeHelper.u16),
			Map.entry("SceWChar32",		TypeHelper.u32),
			Map.entry("SceIntPtr",		TypeHelper.s32),
			Map.entry("SceUIntPtr",		TypeHelper.u32),
			Map.entry("ScePVoid",		TypeHelper.PVOID),
			Map.entry("SceSize",		TypeHelper.u32),
			Map.entry("SceSSize",		TypeHelper.s32),
			Map.entry("SceUIntVAddr",	TypeHelper.u32),
			Map.entry("SceUID",			TypeHelper.s32),
			Map.entry("SceName",		new PointerDataType(TypeHelper.s8)))
		.forEach((alias, dt) ->
				_ctx.dtm.addDataType(new TypedefDataType(destinationCategory, alias, dt), DataTypeConflictHandler.REPLACE_HANDLER)
		);
	
		//Add aliases of SCE types
		DataType SceUID   = _ctx.dtm.getDataType(destinationCategory, "SceUID");
		DataType SceSize  = _ctx.dtm.getDataType(destinationCategory, "SceSize");
		DataType SceSSize = _ctx.dtm.getDataType(destinationCategory, "SceSSize");
		DataType SceInt64 = _ctx.dtm.getDataType(destinationCategory, "SceInt64");
			
		Map.of( "ScePSize", 	SceSize,
				"SceVSize", 	SceSize,
				"ScePSSize", 	SceSSize,
				"SceVSSize", 	SceSSize,
				"SceOff",		SceInt64,
				"ScePID",		SceUID)
		.forEach((alias, dt) ->
				_ctx.dtm.addDataType(new TypedefDataType(destinationCategory, alias, dt), DataTypeConflictHandler.REPLACE_HANDLER)
		);
					
			
		//Add common constants
		EnumDataType sceConstantsDt = new EnumDataType(destinationCategory, "SCE_CONSTANTS", TypeHelper.u32.getLength());
		sceConstantsDt.add("SCE_NULL", 0);
		sceConstantsDt.add("SCE_OK", 0);
		sceConstantsDt.add("SCE_FALSE", 0);
		sceConstantsDt.add("SCE_TRUE", 1);
		sceConstantsDt.add("SCE_UID_INVALID_UID", 0xFFFFFFFFL);
		_ctx.dtm.addDataType(sceConstantsDt, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	//Load a JSON types database - see README for format
	public void loadAndParseToProgram(boolean useExternalSource)  {
		String JSONDataString = null;
		char[] Buffer = new char[8192];
		//Try to load from external source if asked
		if (useExternalSource) {
			GhidraFileChooser fileChooser = new GhidraFileChooser(null);
			String lastDir = Preferences.getProperty(Preferences.LAST_IMPORT_DIRECTORY);
			if (lastDir != null)
				fileChooser.setCurrentDirectory(new File(lastDir));
			fileChooser.setTitle("Choose types database (JSON)");
			fileChooser.setFileFilter(new ExtensionFileFilter("json", "JSON File"));
			fileChooser.setApproveButtonText("Parse selected file");
			fileChooser.rescanCurrentDirectory();
			File dbFile = fileChooser.getSelectedFile();
			//Fallback to internal database if it fails
			if (dbFile != null) {
				FileReader reader;
				try {
					reader = new FileReader(dbFile);
				} catch (FileNotFoundException e) {
					_ctx.logger.appendException(e);
					return;
				}
				
				StringBuilder stringBuilder = new StringBuilder();
				int readSize = 0;
				try {
					while ((readSize = reader.read(Buffer, 0, Buffer.length)) > 0) {
						stringBuilder.append(Buffer, 0, readSize);
					}
					reader.close();
				} catch (IOException e) {
					_ctx.logger.appendException(e);
					return;
				}
				JSONDataString = stringBuilder.toString();
			}
		}
		
		if (JSONDataString == null) {
			if (useExternalSource) _ctx.logger.appendMsg("Loading custom types database failed - using internal database instead");
			
			InputStream inputStream = ResourceManager.getResourceAsStream(TYPES_DB_PATH);
			if (inputStream == null) {
				_ctx.logger.appendMsg("Loading internal types database failed - no additional types provided");
				return;
			}
			
			InputStreamReader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
			StringBuilder stringBuilder = new StringBuilder();
			int readSize = 0;
			try {
				while ((readSize = reader.read(Buffer, 0, Buffer.length)) > 0) {
					stringBuilder.append(Buffer, 0, readSize);
				}
				reader.close();
			} catch (IOException e) {
				_ctx.logger.appendException(e);
				return;
			}
			JSONDataString = stringBuilder.toString();
		}
		
		JSONObject jsonDb;
		try {
			jsonDb = new JSONObject(JSONDataString);
		} catch (JSONException e) {
			_ctx.logger.appendMsg("Loading internal types database failed - database is malformed");
			_ctx.logger.appendMsg("Exception raised : ");
			_ctx.logger.appendException(e);
			return;
		}
		
		Set<String> objNames = jsonDb.toMap().keySet();
		objNames.forEach((name) -> {
			try {
				//Objects are used for structures
				JSONObject obj = jsonDb.getJSONObject(name);
				processStructJSO(name, obj);
			} catch (JSONException e) { //Not an object - must be a mapping or entry is invalid
				try {
					//Strings are used for typedefs
					String typeName = jsonDb.getString(name);
					DataType type = buildDatatypeFromString(typeName);
					if (type == null) {
						_ctx.logger.appendMsg(String.format("Unknown type '%s' (aliased by '%s')", typeName, name));
					}
					else {
						_ctx.dtm.addDataType(type, DataTypeConflictHandler.REPLACE_HANDLER);
					}
				} catch (JSONException e2) { //Not an object nor a string - must be invalid
					_ctx.logger.appendMsg(String.format("Unexpected JSON entity '%s'", name));
				}
			}
		});
	}
	
	//Returns the DataType for an arbitrary type string
	public DataType buildDatatypeFromString(String typeString) {
		//Check that type syntax is valid
		if (!isValidCType(typeString)) {
			_ctx.logger.appendMsg(typeString);
			return null;
		}
		
		Matcher arrayMatcher;
		Matcher funcPtrMatcher;
		Pattern arrayNumPattern;
		try {
			Pattern arrayPattern = Pattern.compile("(?<arrayType>.+?)\\s*(?<arraySize>(?:\\[[0-9]+\\])+)");
			Pattern funcPtrPattern = Pattern.compile("(?<returnType>.+?)\\s*\\((?<functionPointerLevel\\**\\s*)\\)\\s*\\((?<functionArguments>.*?)\\s*\\)");
			arrayNumPattern = Pattern.compile("\\[(?<num>[0-9]+)\\]");
			
			arrayMatcher = arrayPattern.matcher(typeString);
			funcPtrMatcher = funcPtrPattern.matcher(typeString);
		} catch (PatternSyntaxException e) {
			System.err.println("Caught exception while compiling patterns : " + e.getDescription());
			_ctx.logger.appendMsg("!!!!REGEX COMPILE FAIL WHILE PARSING " + typeString + "!!!!");
			_ctx.logger.appendException(e);
			return null;
		}
		
		DataType retDt = null;
		if (funcPtrMatcher.matches()) {
			String returnTypeS = getMatcherKey(typeString, funcPtrMatcher, "returnType");
			int functionPtrLevel = getPointerLevel(getMatcherKey(typeString, funcPtrMatcher, "functionPointerLevel"));
			String functionName = getMatcherKey(typeString, funcPtrMatcher, "functionName");
			String functionArgsS = getMatcherKey(typeString, funcPtrMatcher, "functionArguments");
			
			DataType returnType = getDatatypeFromName(returnTypeS);
			if (returnType == null) {
				_ctx.logger.appendMsg(String.format("Unknown type '%s' for return of function definition '%s'", returnTypeS, functionName));
				return null;
			}
			
			boolean hasVarArgs = false;
			
			String[] functionArgs = functionArgsS.split(",");
			ParameterDefinition[] args = new ParameterDefinition[functionArgs.length];
			for (int i = 0; i < functionArgs.length; i++) {
				String fArg = functionArgs[i].stripTrailing().stripLeading();
				
				//Check for varargs (can only be last argument)
				if (i == (functionArgs.length - 1) && fArg.equals("...")) {
					hasVarArgs = true;
					break;
				}
				
				//Type is always separated from name by either a space, or a *
				int lastTypePos = Integer.max(fArg.lastIndexOf(' '), fArg.lastIndexOf('*'));
				String argType = fArg.substring(0, lastTypePos);
				String argName = fArg.substring(lastTypePos + 1, fArg.length() - 1);
				
				//Check for [] in name
				if (fArg.matches(".+(?:\\[[0-9]*\\])")) {
					//TODO: add * to argType for each []
				}
				
				DataType argDt = getDatatypeFromName(getStrippedTypeName(argType));
				if (argDt == null) {
					_ctx.logger.appendMsg(String.format("Unknown type '%s' for argument %d (%s) of function definition '%s'", argType, i + 1, argName, functionName));
					return null;
				}
				args[i] = new ParameterDefinitionImpl(argName, argDt, null);
			}
			
			FunctionDefinitionDataType functionDt = new FunctionDefinitionDataType(TYPES_DB_CATEGORY, functionName);
			functionDt.setArguments(args);
			functionDt.setVarArgs(hasVarArgs);
			
			retDt = getPointerType(functionDt, functionPtrLevel);
		} else {
			int pointerLevel = getPointerLevel(typeString);
			String strippedName = getStrippedTypeName(typeString);
			retDt = getDatatypeFromName(strippedName);
			if (retDt == null) {
				_ctx.logger.appendMsg(String.format("Unknown type '%s' (needed to build '%s')", strippedName, typeString));
				return null;
			}
			if (pointerLevel > 0) { 
				retDt = getPointerType(retDt, pointerLevel);
			}
		}
		
		//Build array type (if necessary)
		if (arrayMatcher.matches()) {
			do {
				String arraySize = getMatcherKey(typeString, arrayMatcher, "arraySize");
				Matcher arrayNumMatcher = arrayNumPattern.matcher(arraySize);
				if (!arrayNumMatcher.matches()) {
					_ctx.logger.appendMsg(String.format("Malformed array specifier for type '%s'", typeString));
					return null;
				}
				String countStr = getMatcherKey(arraySize, arrayNumMatcher, "num");
				int count = Integer.getInteger(countStr);
				retDt = TypeHelper.makeArray(retDt, count); //Overwrite fullType to allow cascading
			} while (arrayMatcher.find());
		}
		return retDt;
	}
	
	
	
//Private methods
	private String getMatcherKey(String str, Matcher m, String key) {
		return str.substring(m.start(key), m.end(key));
	}
	
	//Get a DataType from name
	private DataType getDatatypeFromName(String tName) {
		//Try to find base data type in primitive types
		if (PRIMITIVE_TYPES_MAP.containsKey(tName))
			return PRIMITIVE_TYPES_MAP.get(tName);
		
		//Try to find in SceXXX types
		DataType r = _ctx.dtm.getDataType(TypeHelper.SCE_TYPES_CATPATH, tName);
		if (r != null) return r;
		
		//Try to find in types we already defined
		r = _ctx.dtm.getDataType(TYPES_DB_CATEGORY, tName);
		if (r != null) return r;
		
		//...
		return null;
	}
			
	//Only checks that there are no illegal characters
	private boolean isValidCType(String typeName) {
		if (!Character.isLetter(typeName.charAt(0))) return false;
		for (int i = 0; i < typeName.length(); i++) {
			char ch = typeName.charAt(i);
			if (!Character.isLetterOrDigit(ch) && !specialCTokens.contains(ch)) return false;
		}
		return true;
	}
			
	//Counts the number of '*' in a string
	private int getPointerLevel(String typeName) {
		int pIdx = typeName.indexOf('*');
		if (pIdx == -1) return 0;
		int pLevel = 1;
		while ((pIdx = typeName.indexOf('*', pIdx)) != -1) {
			pLevel++;
		}
		System.out.println(String.format("[VitaLoader - DEBUG] '%s' -> %s (%d)", typeName, "*".repeat(pLevel), pLevel));
		return pLevel;
	}
		
	//Removes all tokens and whitespace
	private String getStrippedTypeName(String typeName) {
		
		char[] tempBuf = new char[typeName.length() + 1];
		int bufIdx = 0;
		for (int i = 0; i < typeName.length() && bufIdx < tempBuf.length; i++) {
			char ch = typeName.charAt(i);
			if (specialCTokens.contains(ch) || Character.isWhitespace(ch)) continue;
			tempBuf[bufIdx++] = ch;
		}
		tempBuf[bufIdx] = '\0';
		return new String(tempBuf);
	}
		
	//Returns a pointer(-to-pointer-to-...)-to-type type
	//pointerLevel must be >= 0
	private DataType getPointerType(DataType pointedToType, int pointerLevel) {
		if (pointerLevel <= 0) return null;
		if (pointerLevel == 1) return new Pointer32DataType(pointedToType);
		return new Pointer32DataType(getPointerType(pointedToType, pointerLevel-1));
	}
	
	private void processStructJSO(String structName, JSONObject struct) {
		Set<String> fieldNames = struct.toMap().keySet();
		StructureDataType structDt = TypeHelper.createAndGetStructureDataType(TYPES_DB_CATEGORY, structName);
		fieldNames.forEach((fieldName) -> {
			try {
				String fieldTypeS = struct.getString(fieldName);
				DataType fieldDt = buildDatatypeFromString(fieldTypeS);
				if (fieldDt == null) {
					_ctx.logger.appendMsg(String.format("Unknown type '%s' (field '%s' of structure '%s') - structure will not be defined", fieldTypeS, fieldName, structName));
					return;
				}
				structDt.add(fieldDt);
			} catch (JSONException e) {
				_ctx.logger.appendMsg(String.format("Unexpected JSON entity '%s' in structure '%s'.", fieldName, structName));
			}
			_ctx.dtm.addDataType(structDt, DataTypeConflictHandler.REPLACE_HANDLER);
		});
	}
}

