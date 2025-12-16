# Builder

### TODO
- use https://github.com/DarthTon/Blackbone/tree/master instead of rewriting everything? maybe eventually ill do this? for now rewriting it myself might be better just so i learn more

### Features
- helps create specific builds based on target dll, target os, host process, and more
- converts dll into "axe" file
  - removes all pe file attributes that are not needed/used to manually map a DLL file
  - encrypts, hashes, compresses, and/or obfuscates function names (for import table) and sensitive data (in the pe file's sections)
