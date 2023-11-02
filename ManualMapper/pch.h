#pragma once
#pragma comment(lib, "imagehlp")
#pragma comment(lib, "shlwapi")

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#define HexOut std::uppercase << std::hex

#include <windows.h>
#include <TlHelp32.h>
#include <imagehlp.h>
#include <Shlwapi.h>
#include <Psapi.h>
#include <iostream>
#include <fstream>
#include <vector>