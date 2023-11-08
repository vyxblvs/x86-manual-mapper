#include "pch.h"
#include "process.h"
#include "helpers.h"


bool HijackThread()
{
	//Status & constant variables
	bool status = false;						 // Return value
 	constexpr int reserved = NULL;			     // LPVOID lpvReserved
	constexpr int reason   = DLL_PROCESS_ATTACH; // DWORD fdwReason

	const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (!snapshot)
	{
		std::cout << "Failed to take a snapshot of threads\n";
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
					std::cout << "[HijackThread] Failed to open thread (" << GetLastError() << ")\n";
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

	//Getting thread context (GPR's only)
	WOW64_CONTEXT context { NULL };
	context.ContextFlags = WOW64_CONTEXT_CONTROL;
	if (!Wow64GetThreadContext(thread, &context))
	{
		std::cout << "[HijackThread] Failed to get thread context (" << GetLastError() << ")\n";
		goto exit;
	}

	context.Esp -= 4; // LPVOID lpvReserved
	if (!wpm(context.Esp, &reserved, sizeof(LPVOID)))
	{
		std::cout << "Failed to write lpvReserved to stack (" << GetLastError() << ")\n";
		std::cout << "Address: 0x" << HexOut << context.Esp << '\n';
		goto exit;
	}

	context.Esp -= 4; // DWORD fdwReason
	if (!wpm(context.Esp, &reason, sizeof(DWORD)))
	{
		std::cout << "Failed to write fdwReason to stack (" << GetLastError() << ")\n";
		std::cout << "Address: 0x" << HexOut << context.Esp << '\n';
		goto exit;
	}

	context.Esp -= 4; // HINSTANCE hinstDLL
	if (!wpm(context.Esp, &modules[0].ImageBase, sizeof(HINSTANCE)))
	{
		std::cout << "Failed to write hinstDLL to stack (" << GetLastError() << ")\n";
		std::cout << "Address: 0x" << HexOut << context.Esp << '\n';
		goto exit;
	}

	context.Esp -= 4; // Return address
	if (!wpm(context.Esp, &context.Eip, sizeof(DWORD)))
	{
		std::cout << "Failed to write return address to stack (" << GetLastError() << ")\n";
		std::cout << "Address: 0x" << HexOut << context.Esp << '\n';
		goto exit;
	}

	context.Eip = GetEntryPoint(modules[0].image, modules[0].ImageBase);

	if(!Wow64SetThreadContext(thread, &context))
	{
		std::cout << "[HijackThread] Failed to set thread context (" << GetLastError() << ")\n";
		goto exit;
	}

	status = true;

exit:
	ResumeThread(thread);
	CloseHandle(thread);
	return status;
}



bool GetLoadedModules()
{
	DWORD size;
	HMODULE handles[1024];

	if (!EnumProcessModules(process, handles, sizeof(handles), &size))
	{
		std::cout << "[GetLoadedModules] Failed to enumerate process modules (" << GetLastError() << ")\n";
		return false;
	}

	for (UINT x = 0; x < size / sizeof(HMODULE); ++x)
	{
		char path[MAX_PATH];
		const short length = GetModuleFileNameExA(process, handles[x], path, MAX_PATH);
		if (!length)
		{
			std::cout << "[GetLoadedModules] Failed to get module path (" << GetLastError() << ")\n";
			return false;
		}

		LoadedModules.emplace_back(_LoadedModule{ handles[x] });
		LoadedModules.back().name = reinterpret_cast<char*>(malloc(length + 1));

		path[length] = '\0';
		memcpy(LoadedModules.back().name, path, length + 1);
	}

	return true;
}


bool AllocMemory(_module* target)
{
	const LOADED_IMAGE* image = target->image;

	target->BasePtr = VirtualAllocEx(process, NULL, image->FileHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!target->BasePtr)
	{
		std::cout << "[AllocMemory] Failed to allocate memory (" << GetLastError() << ")\n";
		std::cout << "Size: 0x" << HexOut << image->FileHeader->OptionalHeader.SizeOfImage << '\n';
		return false;
	}

	DWORD OldProtection;
	return VirtualProtect(image->MappedAddress, image->SizeOfImage, PAGE_WRITECOPY, &OldProtection);
}


bool WINAPI MapDll(_module* target)
{
	const auto image    = target->image;
	const auto sections = image->Sections;

	//Mapping headers
	if (!wpm(target->BasePtr, image->MappedAddress, sections[0].PointerToRawData)) return false;

	//Mapping sections
	for (UINT x = 0; x < image->NumberOfSections; ++x)
	{
		const DWORD address = target->ImageBase + sections[x].VirtualAddress;
		const void* section = image->MappedAddress + sections[x].PointerToRawData;
		if (!wpm(address, section, sections[x].SizeOfRawData)) return false;
	}

	return true;
}


bool GetProcessHandle(const char* name)
{
	const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!snapshot)
	{
		std::cout << "Failed to take a snapshot of processes (" << GetLastError() << ")\n";
		return false;
	}

	wchar_t wName[MAX_PATH];
	mbstowcs_s(nullptr, wName, name, MAX_PATH);

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	
	if (Process32First(snapshot, &pe32))
	{
		do 
		{
			if (_wcsicmp(wName, pe32.szExeFile) == 0)
			{
				process = OpenProcess(PROCESS_ALL_ACCESS, false, pe32.th32ProcessID);
				if (!process)
				{
					std::cout << "Failed to open process (" << GetLastError() << ")\n";
					std::cout << "PID: " << pe32.th32ProcessID << '\n';
					goto exit;
				}

				BOOL is_x86;
				IsWow64Process(process, &is_x86);
				if (!is_x86)
				{
					std::cout << "Invalid target architecture, process must be running under WOW64\n";
					std::wcout << L"Located process: " << pe32.szExeFile << L'\n';
					process = reinterpret_cast<void*>(CloseHandle(process) * 0);
				}

				goto exit;
			}
		} while (Process32Next(snapshot, &pe32));
	}
	std::cout << "Failed to locate process: " << name << '\n';

exit:
	CloseHandle(snapshot);
	return process != 0;
}