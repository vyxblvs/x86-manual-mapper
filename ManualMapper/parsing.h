#pragma once
#include "pch.h"

//Structs

struct _module
{
	LOADED_IMAGE* image;

	union
	{
		void* BasePtr;
		DWORD ImageBase = 0;
	};
};

struct _LoadedModule
{
	union
	{
		HMODULE handle;
		DWORD base = 0;
	};

	char* name;
	
	union
	{
		HMODULE LocalHandle;
		DWORD LocalBase = 0;
	};
};


//Typedefs

typedef IMAGE_IMPORT_DESCRIPTOR _ImportDescriptor;
typedef IMAGE_BASE_RELOCATION   BaseRelocation;
typedef IMAGE_THUNK_DATA32      ThunkData32;


//Forward Declarations

extern HANDLE process;
extern std::vector<_module> modules;
extern std::vector<_LoadedModule> LoadedModules;

bool GetDependencies(LOADED_IMAGE* image);

void WINAPI ApplyReloction(_module* TargetModule);

bool WINAPI ResolveImports(_module* target);


//Macros

#define ImportDirectory(image) image->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]

#define ExportDirectory(image) image->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]

#define RelocationDirectory(image) image->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]

#define IS_API_SET(image) ImportDirectory(image).Size == NULL

#define SHOULD_RELOCATE(ModulePtr) ModulePtr->ImageBase != ModulePtr->image->FileHeader->OptionalHeader.ImageBase && RelocationDirectory(ModulePtr->image).Size != 0