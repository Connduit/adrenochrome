# Builder

### TODO
- use https://github.com/DarthTon/Blackbone/tree/master instead of rewriting everything? maybe eventually ill do this? for now rewriting it myself might be better just so i learn more
- builder should contain converter, packer, and builder classes
    - converter: dll -> axe or pic
    - packer: packs dll, axe, or pic into a payload like .bin or .cache, or embeds it into the installer/host dlls
    - builder: contains the actual logic and config stuff for what files we want convert and how we want to pack them

### Features
- helps create specific builds based on target dll, target os, host process, and more
- converts dll into "axe" file
  - removes all pe file attributes that are not needed/used to manually map a DLL file
  - encrypts, hashes, compresses, and/or obfuscates function names (for import table) and sensitive data (in the pe file's sections)
