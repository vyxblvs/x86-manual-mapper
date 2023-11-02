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
    SetReloctions(target);
    return ResolveImports(target);
}


int main(int argc, char* argv[])
{
    int status = 0;
    char arguments[3][MAX_PATH];
    if (argc >= 3)
    {
        strncpy(arguments[0], argv[1], MAX_PATH);
        strncpy(arguments[1], argv[2], MAX_PATH);
        strncpy(arguments[2], argv[3], MAX_PATH);
    }

    if (!CFG_CHECK(argc, arguments)) return false;

    if (!GetProcessHandle(arguments[0])) return false;

    modules.emplace_back(_module{ NULL, GetDll(arguments[1])});
    if (!modules.back().image) return false;

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
        if (!SHOULD_RELOCATE(modules[x].ImageBase, modules[x].image)) continue;
        threads.emplace_back(RunThread(DispatchThread, &modules[x]));
    }
    if (!WaitForThreads(&threads)) goto exit;

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