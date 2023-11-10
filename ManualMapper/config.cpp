#include "pch.h"
#include "config.h"
#include "helpers.h"


inline void GetConfigPath(std::string& buffer)
{
	GetModuleFileNameA(nullptr, buffer.data(), MAX_PATH);
	buffer = buffer.substr(0, buffer.find_last_of('\\') + 1) + "cfg.txt";
}


bool SaveConfig(char* argv[])
{
	std::string path(MAX_PATH, NULL);
	GetConfigPath(path);

	std::ofstream file(path);
	if (file.fail())
	{
		std::cerr << "Failed to create/save config file\n";
		file.close();
		return false;
	}

	file << argv[1] << '\n'; // default process
	file << argv[2] << '\n'; // default image

	file.close();
	return true;
}


bool LoadConfig(char* buffer[])
{
	std::string path(MAX_PATH, NULL);
	GetConfigPath(path);

	std::ifstream file(path);
	if (file.fail())
	{
		std::cerr << "Could not open cfg.txt\n";
		return false;
	}

	file.getline(buffer[1], MAX_PATH); // default process
	file.getline(buffer[2], MAX_PATH); // default image

	file.close();
	return true;
}