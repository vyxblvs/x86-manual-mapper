#include "pch.h"
#include "process.h"
#include "parsing.h"
#include "helpers.h"

HANDLE process;
std::vector<MODULE> modules;
std::vector<LOADED_MODULE> LoadedModules;


bool WINAPI DispatchThread(MODULE* target)
{
    if (SHOULD_RELOCATE(target)) ApplyReloction(target);
    return ResolveImports(&target->image);
}


void WINAPI UnloadModules()
{
    for (UINT x = 0; x < LoadedModules.size(); ++x)
    {
        if (LoadedModules[x].handle) FreeLibrary(LoadedModules[x].handle);
        delete[] LoadedModules[x].name;
    }
    LoadedModules.clear();
}


int main(const int argc, char* argv[])
{
    int status = -1;

    //Allocate memory for target data manually if arguments weren't passed
    switch (argc)
    {
    case 1:
        argv[1] = new char[MAX_PATH];
        [[fallthrough]];

    case 2:
        argv[2] = new char[MAX_PATH];
    }

    //Loading or saving target data
    if (argc == 1 || argc == 4)
    {
        std::string buffer(MAX_PATH, NULL);
        GetModuleFileNameA(nullptr, buffer.data(), MAX_PATH);

        std::fstream file(buffer.substr(0, buffer.find_last_of('\\') + 1) + "cfg.txt");
        if (file.fail())
        {
            std::cout << "Failed to open cfg.txt\n";
            return false;
        }

        if (argc == 1)
        {
            file.getline(argv[1], MAX_PATH);
            file.getline(argv[2], MAX_PATH);
        }
        else if (_stricmp(argv[3], "-save") == 0)
        {
            file << argv[1] << '\n';
            file << argv[2] << '\n';
        }

        file.close();
    }

    //Load user specified DLL
    modules.emplace_back(MODULE{ NULL });
    if (!GetDll(argv[2], &modules.back())) return false;

    status = GetProcessHandle(argv[1]);
    switch (argc)
    {
    case 1:
        delete[] argv[2];
        argv[2] = nullptr;
        [[fallthrough]];
    
    case 2:
        delete[] argv[1];
        argv[1] = nullptr;
    }

    if (status)
    {
        if (GetLoadedModules()) // Populating LoadedModules with every module already present in the target process
        {
            //Allocate memory & resolve dependencies
            for (UINT x = 0; x < modules.size(); ++x)
            {
                if (IS_API_SET(modules[x].image)) continue;

                modules[x].ImageBase = reinterpret_cast<DWORD>(VirtualAllocEx(process, nullptr, modules[x].image.NT_HEADERS->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
                if (!modules[x].ImageBase)
                {
                    std::cerr << "Failed to allocate memory (" << GetLastError() << ")\n";
                    std::cerr << "Size: " << HexOut << modules[x].image.NT_HEADERS->OptionalHeader.SizeOfImage << '\n';
                    status = false;
                    break;
                }

                status = GetDependencies(&modules[x].image);
                if (!status) break;
            }

            if (status)
            {
                //Applying relocation & import resolution
                HANDLE* threads = new HANDLE[modules.size()];
                for (UINT x = 0; x < modules.size(); ++x)
                {
                    if (IS_API_SET(modules[x].image)) continue;
                    threads[x] = CreateThreadEx(DispatchThread, &modules[x]);
                }
                for (UINT x = 0; x < modules.size() && status != NULL; ++x)
                {
                    WaitForSingleObject(threads[x], INFINITE);
                    GetExitCodeThread(threads[x], reinterpret_cast<DWORD*>(&status));
                }
                for (UINT x = 0; x < modules.size(); ++x)
                {
                    __pragma(warning(push)) __pragma(warning(disable:6385 6001));
                    CloseHandle(threads[x]);
                    __pragma(warning(pop));
                }

                CreateThreadEx(UnloadModules, nullptr);
                delete[] threads;
                threads = nullptr;

                if (status)
                {
                    //Mapping modules into memory
                    for (UINT x = 0; x < modules.size(); ++x)
                    {
                        if (IS_API_SET(modules[x].image)) continue;
                        status = MapDll(&modules[x]);
                        if (!status) break;
                        if (x > 0)
                        {
                            delete[] modules[x].image.path;
                            delete[] modules[x].image.MappedAddress;
                            memset(&modules[x].image, NULL, sizeof(IMAGE_DATA));
                        }
                    }
                    if (modules.size() > 1) modules.erase(modules.begin() + 1, modules.end());

                    //Running DllMain via thread hijacking
                    if (status)
                    {
                        status = HijackThread();
                        if(status) std::cout << "Successfully mapped dll!\n";
                    }
                }
            }
        }
    }
    
    CloseHandle(process);
    return status;
}