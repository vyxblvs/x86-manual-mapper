#pragma once
#include "pch.h"

//Structs

struct IMAGE_DATA
{
	char* path = nullptr;

	union
	{
		HMODULE handle;
		const char* LocalBase = nullptr;
	};

	const IMAGE_NT_HEADERS32* NT_HEADERS = nullptr;
	const IMAGE_SECTION_HEADER* sections = nullptr;
};

struct MODULE
{
	DWORD ImageBase = NULL;
	IMAGE_DATA image;
};


//Forward Declarations

extern HANDLE process;
extern std::vector<MODULE> modules, LoadedModules;

bool GetDll(const char* path, MODULE* const buffer);

bool GetDependencies(const IMAGE_DATA* const image);

void ApplyReloction(const MODULE* TargetModule);

bool ResolveImports(const IMAGE_DATA* const target);


//Macros

#define DataDirectory(image, directory) image->NT_HEADERS->OptionalHeader.DataDirectory[directory]

#define IsDirectory(data) (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && strcmp(data.cFileName, ".") && strcmp(data.cFileName, ".."))

#define IS_API_SET(image) DataDirectory((&image), IMAGE_DIRECTORY_ENTRY_IMPORT).Size == 0

#define SHOULD_RELOCATE(ModulePtr) ModulePtr.ImageBase != ModulePtr.image.NT_HEADERS->OptionalHeader.ImageBase && DataDirectory((&ModulePtr.image), IMAGE_DIRECTORY_ENTRY_BASERELOC).Size != 0