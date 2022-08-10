# VitaLoader
PS Vita ELF loader for Ghidra

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

## Updating
Download the [latest release](https://github.com/CreepNT/VitaLoader/releases) for the Ghidra version you use.
Open Ghidra, select `File` > `Install Extensions...` and untick the checkbox next to `VitaLoader`. Restart Ghidra, then proceed like for the first installation.

## Building
You will need to [install  Gradle](https://gradle.org/install/) in order to be able to build the extension.

Run `gradle` / `gradle.bat` in the repository directory.
Make sure to pass `-PGHIDRA_INSTALL_DIR=<your Ghidra install>` if the environement variable `GHIDRA_INSTALL_DIR` isn't set.

It seems building the extension for Ghidra 9.xx releases is no longer possible. Assistance in getting the project to build will only be provided for the latest Ghidra version.

## Bug reports
Please report any error you encounter in the [Issues Tracker](https://github.com/CreepNT/VitaLoader/issues).

**Make sure to update to the latest version if you encounter a bug before reporting it. Bug reports for old versions will be rejected.**

**Make sure you are importing a Vita ELF. Non-Vita ELFs are NOT supported and such bug reports will be rejected.**

## Future plans
* Add an Analysis option to re-parse all structures
 * This would allow using an updated NID database without needing to reimport the file
* Parse the `exidx`/`extab` sections (would that even be useful?)
* Add internal database support
* Add support for a type database file

# Credits
* astrelsky and all contributors - [GhidraOrbis](https://github.com/astrelsky/GhidraOrbis)
* xerpi and all contributors - [GhidraVitaLoader script](https://github.com/xerpi/GhidraVitaLoader)
* EsotericSoftware - [YamlBeans](https://github.com/EsotericSoftware/yamlbeans)
