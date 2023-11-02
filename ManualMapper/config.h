#pragma once

//Forward Declarations

bool SaveConfig(char* argv[3]);

bool LoadConfig(char* buffer[3]);

LOADED_IMAGE* GetDll(const char* path);


//Macros

#define VALID_DLL(image) (image->Characteristics & (IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL) && !(image->FileHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA))

#define CFG_CHECK(status, argv) (status == 4 && _stricmp(argv[3], "-save") == 0 ? SaveConfig(argv) : (argc < 3 ? LoadConfig(argv) : true))