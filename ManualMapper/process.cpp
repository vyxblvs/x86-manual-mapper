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

	//Getting thread context (GPR's only)
	WOW64_CONTEXT context { NULL };
	context.ContextFlags = WOW64_CONTEXT_CONTROL; //Request general purpose registers
	if (!Wow64GetThreadContext(thread, &context))
	{
		std::cout << "Failed to get thread context (" << GetLastError() << ")\n";
		goto exit;
	}

	context.Esp -= 4; //LPVOID lpvReserved
	if (!wpm(context.Esp, &reserved, sizeof(int))) goto exit;

	context.Esp -= 4; //DWORD fdwReason
	if (!wpm(context.Esp, &reason, sizeof(int))) goto exit;

	context.Esp -= 4; //HINSTANCE hinstDLL
	if (!wpm(context.Esp, &modules[0].ImageBase, sizeof(DWORD))) goto exit;

	context.Esp -= 4; //Return address
	if (!wpm(context.Esp, &context.Eip, sizeof(DWORD))) goto exit;

	context.Eip = GetEntryPoint(modules[0].image, modules[0].ImageBase);

	if(!Wow64SetThreadContext(thread, &context))
	{
		std::cout << "Failed to set thread context (" << GetLastError() << ")\n";
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


bool AllocMemory(_module* target)
{
	const LOADED_IMAGE* image = target->image;

	target->BasePtr = VirtualAllocEx(process, NULL, image->FileHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!target->BasePtr)
	{
		std::cout << "Failed to allocate memory (" << GetLastError() << ")\n";
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
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!snapshot)
	{
		std::cout << "Failed to take a snapshot of processes (" << GetLastError() << ")\n";
		return NULL;
	}

	wchar_t* wName = new wchar_t[MAX_PATH];
	mbstowcs(wName, name, MAX_PATH);
	
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
					std::cout << "Process ID: " << pe32.th32ProcessID << '\n';
					goto exit;
				}

				BOOL is_x86;
				IsWow64Process(process, &is_x86);
				if (!is_x86)
				{
					std::cout << "Invalid target architecture, process must be running under WOW64\n";
					std::wcout << L"Located process: " << pe32.szExeFile << L'\n';
					process = reinterpret_cast<void*>(CloseHandle(process) * 0);
					goto exit;
				}

				goto exit;
			}
		} while (Process32Next(snapshot, &pe32));
	}
	std::cout << "Failed to locate " << name << '\n';

exit:
	delete[](wName);
	CloseHandle(snapshot);
	return process != 0;
}