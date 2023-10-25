#include "pch.h"
#include "process.h"
#include "helpers.h"


DWORD HijackThread()
{
	const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (!snapshot)
	{
		std::cout << "Failed to take a snapshot of current threads\n";
		return false;
	}

	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);
	const DWORD PID = GetProcessId(process);
	HANDLE thread = nullptr;

	//Locating a thread within the target process
	if (Thread32First(snapshot, &te32))
	{
		do
		{
			if (te32.th32OwnerProcessID == PID)
			{
				thread = OpenThread(THREAD_ALL_ACCESS, false, te32.th32ThreadID);
				if (!thread)
				{
					std::cout << "Failed to open thread (" << GetLastError() << ")\n";
					return false;
				}

				//Making sure the suspend count is 0
				if (Wow64SuspendThread(thread) != 0)
				{
					ResumeThread(thread);
					CloseHandle(thread);
					continue;
				}

				CloseHandle(snapshot);
				break;
			}
		} while (Thread32Next(snapshot, &te32));
	}

	if (thread == nullptr)
	{
		std::cout << "Failed to locate valid thread\n";
		return false;
	}

	DWORD status = NULL;
	WOW64_CONTEXT context { NULL };
	context.ContextFlags = WOW64_CONTEXT_CONTROL; //Request general purpose registers
	if (!Wow64GetThreadContext(thread, &context))
	{
		std::cout << "Failed to get thread context (" << GetLastError() << ")\n";
		CloseHandle(thread);
		return false;
	}

	constexpr int reserved = NULL;			     //LPVOID lpvReserved
	constexpr int reason   = DLL_PROCESS_ATTACH; //DWORD fdwReason

	context.Esp -= 4; //LPVOID lpvReserved
	if (!wpm(process, context.Esp, &reserved, sizeof(int))) goto exit;

	context.Esp -= 4; //DWORD fdwReason
	if (!wpm(process, context.Esp, &reason, sizeof(int))) goto exit;

	context.Esp -= 4; //HINSTANCE hinstDLL
	if (!wpm(process, context.Esp, &modules[0].ImageBase, sizeof(DWORD))) goto exit;

	context.Esp -= 4; //Return address
	if (!wpm(process, context.Esp, &context.Eip, sizeof(DWORD))) goto exit;

	context.Eip = ConvertRva<DWORD>(modules[0].ImageBase, modules[0].image->FileHeader->OptionalHeader.AddressOfEntryPoint, modules[0].image);

	if(!Wow64SetThreadContext(thread, &context))
	{
		std::cout << "Failed to set thread context (" << GetLastError() << ")\n";
		goto exit;
	}

    ResumeThread(thread);
	status = true;

exit:
	CloseHandle(thread);
	return status;
}


//Check which modules are loaded into ac_client.exe to avoid remapping
bool GetLoadedModules()
{
	DWORD size;
	HMODULE handles[100];

	if (!EnumProcessModules(process, handles, sizeof(handles), &size))
	{
		std::cout << "Failed to enumerate process modules (" << GetLastError() << ")\n";
		return false;
	}

	for (DWORD x = 0; x < size / sizeof(HMODULE); ++x)
	{
		char buffer[MAX_PATH];
		if (!GetModuleFileNameExA(process, handles[x], buffer, MAX_PATH))
		{
			std::cout << "Failed to get module path (" << GetLastError() << ")\n";
			return false;
		}

		LoadedModules.emplace_back(_LoadedModule{ NULL, reinterpret_cast<DWORD>(handles[x]), buffer });
	}

	return true;
}


//Get ac_client.exe PID
DWORD GetPID()
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!snapshot)
	{
		std::cout << "Failed to take a snapshot of processes (" << GetLastError() << ")\n";
		return NULL;
	}

	if (Process32First(snapshot, &pe32))
	{
		do
		{
			if (_wcsicmp(L"ac_client.exe", pe32.szExeFile) == 0)
			{
				CloseHandle(snapshot);
				return pe32.th32ProcessID;
			}

		} while (Process32Next(snapshot, &pe32));
	}

	std::cout << "Failed to locate ac_client.exe\n";
	CloseHandle(snapshot);
	return NULL;
}