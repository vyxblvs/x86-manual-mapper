#pragma once
#include "pch.h"

//Structs

struct _module
{
	LOADED_IMAGE* image;

	union
	{
		DWORD ImageBase;
		void* BasePtr;
	};
};

struct _LoadedModule
{
	union
	{
		HMODULE LocalHandle;
		DWORD LocalBase = 0;
	};

	DWORD base = 0;
	std::string name;
};


//Typedefs

typedef std::vector<_module>       ModuleVec;
typedef std::vector<_LoadedModule> LModuleVec;

typedef IMAGE_IMPORT_DESCRIPTOR _ImportDescriptor;
typedef IMAGE_BASE_RELOCATION   BaseRelocation;
typedef IMAGE_THUNK_DATA32      ThunkData32;


//Forward Declarations

extern HANDLE     process;
extern ModuleVec  modules;
extern LModuleVec LoadedModules;


bool FindModuleDir(const char* target, const std::string dir, _module* buffer);

bool GetDependencies(LOADED_IMAGE* image);

bool WINAPI SetReloctions(_module* TargetModule);

bool WINAPI ResolveImports(_module* target);


//Macros

#define ImportDirectory(image) image->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]

#define ExportDirectory(image) image->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]

#define RelocationDirectory(image) image->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]