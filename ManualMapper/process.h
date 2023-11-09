#pragma once
#include "parsing.h"

//Forward Declarations

bool HijackThread();

bool GetProcessHandle(const char* name);

bool AllocMemory(_module* target);

bool MapDll(_module* target);

bool GetLoadedModules();


//Macros

#define RunThread(target, buffer) CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(target), buffer, NULL, nullptr)

#define GetEntryPoint(image, base) base + image->FileHeader->OptionalHeader.AddressOfEntryPoint