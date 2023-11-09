#include "pch.h"
#include "config.h"
#include "process.h"
#include "parsing.h"
#include "helpers.h"

HANDLE process;
std::vector<_module> modules;
std::vector<_LoadedModule> LoadedModules;


bool WINAPI DispatchThread(_module* target)
{
    if (SHOULD_RELOCATE(target)) ApplyReloction(target);
    return ResolveImports(target);
}


int main(int argc, char* argv[])
{
    int status = 0;
    if (argc < 3)
    {
        status = -1;

        argv[2] = new char[MAX_PATH];
        if (argc == 1)
        {
            argv[1] = new char[MAX_PATH];
            status = -2;
        }
    }

    if (!CFG_CHECK(argc, argv)) return false;

    if (!GetProcessHandle(argv[1])) return false;

    modules.emplace_back(_module{ GetDll(argv[2])});
    if (!modules.back().image) return false;

    if (status < 0)
    {
        delete[] argv[1];
        if(status == -2) delete[] argv[2];
    }

    std::vector<HANDLE> threads;

    if (!GetLoadedModules()) goto exit;

    for (UINT x = 0; x < modules.size(); ++x)
    {
        if (IS_API_SET(modules[x].image)) continue;

        if (!AllocMemory(&modules[x])) goto exit;

        if (!GetDependencies(modules[x].image)) goto exit;
    }

    for (UINT x = 0; x < modules.size(); ++x)
    {
        if (IS_API_SET(modules[x].image)) continue;
        threads.emplace_back(RunThread(DispatchThread, &modules[x]));
    }
    if (!WaitForThreads(threads)) goto exit;

    for (UINT x = 0; x < modules.size(); ++x)
    {
        if (IS_API_SET(modules[x].image)) continue;
        if (!MapDll(&modules[x])) goto exit;
    }

    if (!HijackThread()) goto exit;

    std::cout << "Successfully mapped dll!\n";
    status = true;

exit:
    CloseHandle(process);
    return status;
}