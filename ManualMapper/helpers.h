#pragma once
#include "parsing.h"

//Forward Declarations

bool WaitForThreads(std::vector<HANDLE>& buffer);

bool CheckModules(const char* target);

_LoadedModule* FindLoadedModule(const char* name);

DWORD GetOffset(DWORD rva, LOADED_IMAGE* image);

std::string PathToImage(std::string path);


//Macros

template <typename ReturnType, typename ParamType> auto ConvertRva(ParamType base, DWORD rva, LOADED_IMAGE* image) -> ReturnType
{
	return reinterpret_cast<ReturnType>(reinterpret_cast<BYTE*>(base) + GetOffset(rva, image));
}

#define CheckAttribs(data) (data.dwFileAttributes & FILE_ATTRIBUTE_DEVICE || data.dwFileAttributes >= 256)

#define IsDirectory(data) (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && strcmp(data.cFileName, ".") && strcmp(data.cFileName, ".."))

#define wpm(address, buffer, size) WriteProcessMemory(process, reinterpret_cast<LPVOID>(address), buffer, size, nullptr)

#define HexOut std::uppercase << std::hex