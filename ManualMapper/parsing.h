#pragma once
#include "pch.h"

//Structs

struct IMAGE_DATA
{
	char* name;

	union
	{
		BYTE* MappedAddressPtr;
		DWORD MappedAddress;
	};

	IMAGE_NT_HEADERS32* NT_HEADERS;
	IMAGE_SECTION_HEADER* sections;
};

struct MODULE
{
	IMAGE_DATA image;

	union
	{
		void* BasePtr;
		DWORD ImageBase;
	};
};

struct LOADED_MODULE
{
	DWORD base = 0;
	char* name;
	
	union
	{
		HMODULE LocalHandle;
		DWORD LocalBase;
	};
};


//Forward Declarations

extern HANDLE process;
extern std::vector<MODULE> modules;
extern std::vector<LOADED_MODULE> LoadedModules;

bool GetDll(const char* path, MODULE* buffer);

bool GetDependencies(const IMAGE_DATA* image);

void ApplyReloction(const MODULE* TargetModule);

bool ResolveImports(const MODULE* target);


//Macros

#define ImportDirectory(image) image->NT_HEADERS->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]

#define ExportDirectory(image) image->NT_HEADERS->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]

#define RelocationDirectory(image) image->NT_HEADERS->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]

#define IS_API_SET(image) ImportDirectory((&image)).Size == NULL

#define SHOULD_RELOCATE(ModulePtr) ModulePtr->ImageBase != ModulePtr->image.NT_HEADERS->OptionalHeader.ImageBase && RelocationDirectory((&ModulePtr->image)).Size != 0