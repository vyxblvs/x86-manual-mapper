#pragma once

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#define TargetPath "c:\\users\\john\\source\\repos\\acmenu2.0\\release\\acmenu2.0.dll"
#define HexOut std::uppercase << std::hex

#include <windows.h>
#include <TlHelp32.h>
#include <imagehlp.h>
#include <Shlwapi.h>
#include <Psapi.h>
#include <iostream>
#include <vector>