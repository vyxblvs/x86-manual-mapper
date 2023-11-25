#pragma once
#include "parsing.h"

//Forward Declarations

bool GetProcessHandle(const char* const name);

bool GetLoadedModules();

bool MapDll(const MODULE* const target);

bool HijackThread();

//Macros

#define wpm(address, buffer, size) WriteProcessMemory(process, reinterpret_cast<void*>(address), buffer, size, nullptr)