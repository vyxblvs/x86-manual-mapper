#include "pch.h"
#include "process.h"
#include "parsing.h"
#include "helpers.h"

HANDLE process;
ModuleVec  modules;
LModuleVec LoadedModules;

int main()
{
    const DWORD PID = GetPID();
    if (!PID) return false;

    modules.push_back(_module{ ImageLoad(TargetPath, nullptr) });
    if (!modules.back().image)
    {
        std::cout << "Failed to load image (" << GetLastError() << ")\n";
        return false;
    }

    std::vector<HANDLE> threads; //initialized early to allow goto statements
    process = OpenProcess(PROCESS_ALL_ACCESS, false, PID);
    if (!process)
    {
        std::cout << "Failed to open handle to ac_client.exe (" << GetLastError() << ")\n";
        return false;
    }

    if (!GetLoadedModules()) 
        goto exit;


    for (UINT x = 0; x < modules.size(); ++x)
    {
        if (!AllocMemory(&modules[x]))
            goto exit;

        if (!GetDependencies(modules[x].image))
            goto exit;
    }


    for (UINT x = 0; x < modules.size(); ++x)
        threads.emplace_back(RunThread(&SetReloctions, &modules[x])); 

    if (!WaitForThreads(&threads)) goto exit;
    
    for (UINT x = 0; x < modules.size(); ++x)
        threads.emplace_back(RunThread(&ResolveImports, &modules[x]));

    if (!WaitForThreads(&threads)) goto exit;


    if (!HijackThread()) goto exit;


    std::cout << "Successfully mapped dll!\n";
    CloseHandle(process);
    return true;

exit:
    CloseHandle(process);
    return false;
}