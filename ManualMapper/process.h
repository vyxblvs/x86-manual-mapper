#pragma once
#include "parsing.h"

//Forward Declarations

bool GetProcessHandle(const char* name);

bool GetLoadedModules();

bool MapDll(const MODULE* target);

bool HijackThread();

//Macros

#define __CreateThread(address, param) CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(address), param, NULL, nullptr) 