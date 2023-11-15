#include "pch.h"
#include "config.h"
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

    if (!CMD_CHECK(argc, argv)) return false; // Check if "-save" was passed as command line argument, save target data if so
    if (!CFG_CHECK(argc, argv)) return false; // Load default target info if none were passed as command line argument

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

                modules[x].BasePtr = VirtualAllocEx(process, nullptr, modules[x].image.NT_HEADERS->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (!modules[x].BasePtr)
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
                    threads[x] = CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(DispatchThread), &modules[x], NULL, nullptr);
                }
                for (UINT x = 0; x < modules.size() && status != NULL; ++x)
                {
                    WaitForSingleObject(threads[x], INFINITE);
                    GetExitCodeThread(threads[x], reinterpret_cast<DWORD*>(&status));
                }
                for (UINT x = 0; x < modules.size(); ++x)
                {
                    __disable(6385 6001);
                    CloseHandle(threads[x]);
                    __enable;
                }
                LoadedModules.clear();
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
                        if (x > 0) delete[] modules[x].image.MappedAddressPtr;
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