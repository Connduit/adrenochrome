// TODO: 
// this should be the "custom" loader


#ifndef ADRENOCHROME_LOADER_H
#define ADRENOCHROME_LOADER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>


DWORD WINAPI startEngine(LPVOID lpParam );// starts the "engine.axe" logic

int loadAXE();

// engine.dll is embedded in a PE section of loader.dll
void loadFromSection();

// engine.dll is encrypted/compressed on the disk (as a .bin/.data file?)
void loadFromDisk();

void ManualMapDLL();
void ManualMapAXE();
void ManualMapPIC();


#endif