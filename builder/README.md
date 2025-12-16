# Builder

### Features
- helps create specific builds based on target dll, target os, host process, and more
- converts dll into "axe" file
  - removes all pe file attributes that are not needed/used to manually map a DLL file
  - encrypts, hashes, compresses, and/or obfuscates function names (for import table) and sensitive data (in the pe file's sections)
