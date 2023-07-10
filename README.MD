# VitaLoader
PS Vita ELF loader for Ghidra

**VitaLoader has been deprecated as it does not work on Ghidra version 10.2 or higher due to changes inside the Ghidra codebase.**
Please consider using [VitaLoader Redux](https://github.com/CreepNT/VitaLoaderRedux) instead, as this repository is no longer maintained.

## Features
VitaLoader can be used in place of the Ghidra ELF loader to load SCE-specific ELFs for PSVita. **Attempting to load non-Vita ELFs will not work properly and is not supported - use the regular ELF loader instead.**
 * Supports all SCE ELF types (`ET_SCE_EXEC`, `ET_SCE_RELEXEC`, `ET_SCE_PSP2RELEXEC`) and generic ELF types (`ET_REL`/`ET_EXEC`/`ET_CORE`) *that follow the SCE format*
 * True entrypoint is located using the `SceModuleInfo` instead of the ELF header's `e_entry`
 * All imports and exports are marked up exports and imports of the module
   * All exports and imports can be automatically named using a user-provided NID database
   * Imports are sorted based on the module they are imported from. Exports are not sorted as it doesn't seem possible yet.
 * `SceProcessParam` is parsed, marking up all functions involved in the Malloc Replacement functionality
 * DTrace probes structures are parsed, marking up all DTrace probes (for kernel modules)
 * Syscall exports are marked up when appropriate (for kernel modules)
 * Basic SCE datatypes are added to the project automatically

## Installation
Download the [latest release](https://github.com/CreepNT/VitaLoader/releases) for the Ghidra version you use.
Open Ghidra, select `File` > `Install Extensions...`, click on the green `+` and select the `.zip` you just downloaded.
Ghidra should ask you to restart in order for changes to take effect, do so.

## Building
You will need to [install  Gradle](https://gradle.org/install/) in order to be able to build the extension.

Run `gradle` / `gradle.bat` in the repository directory.
Make sure to pass `-PGHIDRA_INSTALL_DIR=<your Ghidra install>` if the environement variable `GHIDRA_INSTALL_DIR` isn't set.

It seems building the extension for Ghidra 9.xx releases is no longer possible. Assistance in getting the project to build will only be provided for the latest Ghidra version.

## Known bugs
* Import thunks may not be marked up (cause unknown)
* VitaSDK moduled with no export cannot be imported ("malformed" SceModuleInfo improperly parsed)
* VitaLoader will not work if GhidraOrbis is installed

# Credits
* astrelsky and all contributors - [GhidraOrbis](https://github.com/astrelsky/GhidraOrbis)
* xerpi and all contributors - [GhidraVitaLoader script](https://github.com/xerpi/GhidraVitaLoader)
* EsotericSoftware - [YamlBeans](https://github.com/EsotericSoftware/yamlbeans)
