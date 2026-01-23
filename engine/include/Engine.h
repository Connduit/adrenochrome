#ifndef ADRENOCHROME_ENGINE_H
#define ADRENOCHROME_ENGINE_H

//#define DLLEXPORT __declspec(dllexport)

#include <stddef.h>

struct Engine
{
    struct Dispatcher *dispatcher;
    struct Loader *loader;
    struct Config *config;
    //struct DynamicConfig *dynamicConfig;
};

struct ModuleVtable // TODO: rename? 
{
    int (*init)(void *);
    int (*handle)(void *, void *);
    int (*shutdown)(void *);
};

struct os_api
{
    void *(*alloc)(size_t);
    void (*free)(void *);
    //int (*create_thread)(...);
};


//
// dispatcher: routes commands/events to the correct module, manages callbacks
// void dispatcher();

//
// loader: does the "backend" part of loading modules. mapping and etc... 
// void loader();

//
// hash: hashing of strings, module names, and commands
// void hash();

//
// crypto: encryption/decryption, integrity verification, possibly key handling?
// void crypto();
// void encrypt();
// void decrypt();

//
// package: module manager. keeps track of modules and when they need to be loaded/unloaded. keeps track of metadata, state, and integrity. provides a way and interface for other modules to interact with the engine.axe
// void package();

//
// config: stores runtime configuration, exposes read/update APIs, used by modules to obtain settings
// TODO: add DynConfig?
// void config();

//
// memory: custom allocation routines, memory tracking, hides standard allocators from modules?
// void memory();

//
// c run time calls: string handling, math, basic utils. needed to prevent modules from directly importing CRT symbols. Provides abtraction to c APIs
// void crt();  // c rutime (calls)

//
// runtime / os abstraction: wraps os-level functionality so modules don't call win32 APIs directly. Provides abstraction to Windows APIs
// void osrt(); // OS runtime (calls)

#endif