#pragma once
#include "parsing.h"

//Forward Declarations

DWORD HijackThread();

DWORD GetPID();

bool GetLoadedModules();


//Macros

#define RunThread(target, buffer) (CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(target), buffer, NULL, nullptr))