#pragma once
#include "pch.h"

//Structs

struct IMAGE_DATA
{
	char* name;
	const char* MappedAddress;
	const IMAGE_NT_HEADERS32* NT_HEADERS;
	const IMAGE_SECTION_HEADER* sections;
};

struct MODULE
{
	IMAGE_DATA image;
	DWORD ImageBase;
};

struct LOADED_MODULE
{
	DWORD base = 0;
	char* name;
	HMODULE handle;
};


//Forward Declarations

extern HANDLE process;
extern std::vector<MODULE> modules;
extern std::vector<LOADED_MODULE> LoadedModules;

bool GetDll(const char* path, MODULE* const buffer);

bool GetDependencies(const IMAGE_DATA* const image);

void ApplyReloction(const MODULE* TargetModule);

bool ResolveImports(const IMAGE_DATA* const target);


//Macros

#define DataDirectory(image, directory) image->NT_HEADERS->OptionalHeader.DataDirectory[directory]

#define IS_API_SET(image) DataDirectory((&image), IMAGE_DIRECTORY_ENTRY_IMPORT).Size == 0

#define SHOULD_RELOCATE(ModulePtr) ModulePtr->ImageBase != ModulePtr->image.NT_HEADERS->OptionalHeader.ImageBase && DataDirectory((&ModulePtr->image), IMAGE_DIRECTORY_ENTRY_BASERELOC).Size != 0