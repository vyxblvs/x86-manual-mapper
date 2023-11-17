#pragma once
#include "parsing.h"

//Forward Declarations

bool GetProcessHandle(const char* name);

bool GetLoadedModules();

bool MapDll(const MODULE* target);

bool HijackThread();

//Macros

#define wpm(address, buffer, size) WriteProcessMemory(process, reinterpret_cast<void*>(address), buffer, size, nullptr)