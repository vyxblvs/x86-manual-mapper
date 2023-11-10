#pragma once
#include "pch.h"
#include "helpers.h"

//Forward Declarations

bool SaveConfig(char* argv[]);

bool LoadConfig(char* buffer[]);


//Macros

#define CMD_CHECK(argc, argv) (argc == 4 && _stricmp(argv[3], "-save") == 0 ? SaveConfig(argv) : true)

#define CFG_CHECK(argc, argv) (argc < 3 ? LoadConfig(argv) : true)