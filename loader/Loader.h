// TODO: 
// this should be the "custom" loader


#ifndef ADRENOCHROME_LOADER_H
#define ADRENOCHROME_LOADER_H


// engine.dll is embedded in a PE section of loader.dll
void loadFromSection();

// engine.dll is encrypted/compressed on the disk (as a .bin/.data file?)
void loadFromDisk();

void ManualMapDLL();
void ManualMapAXE();
void ManualMapPIC();


#endif