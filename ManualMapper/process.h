#pragma once
#include "parsing.h"

//Forward Declarations

bool HijackThread();

bool GetProcessHandle(const char* name);

bool AllocMemory(_module* target);

bool WINAPI MapDll(_module* target);

bool GetLoadedModules();


//Macros

#define RunThread(target, buffer) CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(target), buffer, NULL, nullptr)

#define GetEntryPoint(image, base) base + image->FileHeader->OptionalHeader.AddressOfEntryPoint

#define THREAD_REQUIRED_ACCESS (THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME)