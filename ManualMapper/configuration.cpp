#include "pch.h"
#include "config.h"
#include "helpers.h"


inline void GetConfigPath(std::string& buffer)
{
	GetModuleFileNameA(nullptr, buffer.data(), MAX_PATH);
	buffer = buffer.substr(0, buffer.find_last_of('\\') + 1) + "cfg.txt";
}


bool SaveConfig(char* argv[3])
{
	std::string path(MAX_PATH, NULL);
	GetConfigPath(path);

	std::ofstream file(path);
	if (file.fail())
	{
		std::cout << "Failed to create/save config file\n";
		file.close();
		return false;
	}

	file << argv[1] << '\n'; // default process
	file << argv[2] << '\n'; // default image

	file.close();
	return true;
}


bool LoadConfig(char* buffer[3])
{
	std::string path(MAX_PATH, NULL);
	GetConfigPath(path);

	std::ifstream file(path);
	if (file.fail())
	{
		std::cout << "Could not open cfg.txt\n";
		return false;
	}

	file.getline(buffer[1], MAX_PATH);
	file.getline(buffer[2], MAX_PATH);

	file.close();
	return true;
}


LOADED_IMAGE* GetDll(const char* path)
{
	if (!GetFileAttributesA(path) && GetLastError() == (ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND))
	{
		std::cout << "Invalid file path provided: " << path << '\n';
		return nullptr;
	}

	LOADED_IMAGE* image = ImageLoad(path, nullptr);
	if (!image)
	{
		std::cout << "[GetDll()] Failed to load image (" << GetLastError() << ")\n";
		std::cout << "Path: " << path << '\n';
		return nullptr;
	}

	if (!VALID_DLL(image))
	{
		std::cout << "Invalid image characteristics: " << HexOut << image->Characteristics << " | 0x" << image->FileHeader->OptionalHeader.DllCharacteristics << '\n';
		std::cout << "DLL must be a valid x86 image\n";
		return nullptr;
	}

	return image;
}