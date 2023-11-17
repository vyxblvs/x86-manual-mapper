#include "pch.h"
#include "process.h"
#include "helpers.h"


bool GetProcessHandle(const char* const name)
{
	const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Failed to take a snapshot of processes (" << GetLastError() << ")\n";
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
				process = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, pe32.th32ProcessID);
				if (!process)
				{
					std::cerr << "Failed to open process (" << GetLastError() << ")\n";
					std::cerr << "PID: " << pe32.th32ProcessID << '\n';
					goto exit;
				}

				BOOL is_x86;
				IsWow64Process(process, &is_x86);
				if (!is_x86)
				{
					std::cerr << "Invalid target architecture, process must be running under WOW64\n";
					std::wcerr << L"Located process: " << pe32.szExeFile << L'\n';
					process = reinterpret_cast<void*>(CloseHandle(process) * 0);
				}

				goto exit;
			}
		} while (Process32Next(snapshot, &pe32));
	}
	std::cerr << "Failed to locate process: " << name << '\n';

exit:
	CloseHandle(snapshot);
	return process != 0;
}


bool GetLoadedModules()
{
	DWORD size;
	HMODULE handles[1024];

	if (!EnumProcessModules(process, handles, sizeof(handles), &size))
	{
		std::cerr << "Failed to enumerate process modules (" << GetLastError() << ")\n";
		return false;
	}

	for (UINT x = 0; x < size / sizeof(HMODULE); ++x)
	{
		char path[MAX_PATH + 1];
		const UINT length = GetModuleFileNameExA(process, handles[x], path, MAX_PATH);
		if (!length || length > MAX_PATH)
		{
			std::cerr << "[GetLoadedModules()] Failed to get module path (" << GetLastError() << ")\n";
			return false;
		}

		path[length] = '\0';
		LoadedModules.emplace_back(LOADED_MODULE{ reinterpret_cast<DWORD>(handles[x]) });
		LoadedModules.back().name = new char[length + 1];
		strcpy_s(LoadedModules.back().name, length + 1, path);
	}

	return true;
}


bool MapDll(const MODULE* const target)
{
	const IMAGE_DATA* const image = &target->image;
	const IMAGE_SECTION_HEADER* const sections = image->sections;

	//Mapping headers
	if (!wpm(target->ImageBase, image->MappedAddress, sections[0].PointerToRawData))
	{
		std::cerr << "Failed to map PE headers into memory (" << GetLastError() << ")\n";
		std::cerr << "Image: " << image->path << '\n';
		return false;
	}

	DWORD old;
	VirtualProtectEx(process, reinterpret_cast<void*>(target->ImageBase), sections[0].PointerToRawData, PAGE_READONLY, &old);

	//Mapping sections
	for (UINT x = 0; x < image->NT_HEADERS->FileHeader.NumberOfSections; ++x)
	{
		void* const address = reinterpret_cast<void*>(target->ImageBase + sections[x].VirtualAddress);
		const void* const section = image->MappedAddress + sections[x].PointerToRawData;
		if (!wpm(address, section, sections[x].SizeOfRawData))
		{
			std::cerr << "Failed to map section into memory (" << GetLastError() << ")\n";
			std::cerr << "Section: " << sections[x].Name << '\n';
			std::cerr << "Image: " << image->path << '\n';
			return false;
		}
		else VirtualProtectEx(process, address, sections[x].SizeOfRawData, sections[x].Characteristics / 0x1000000, &old);
	}

	return true;
} 


bool HijackThread()
{
	//Status & constant variables
	bool status = false;
	constexpr int reserved = NULL;
	constexpr int reason   = DLL_PROCESS_ATTACH;

	const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Failed to take a snapshot of threads\n";
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
				thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, te32.th32ThreadID);
				if (!thread) continue;

				CloseHandle(snapshot);
				break;
			}
		} while (Thread32Next(snapshot, &te32));
	}
	if (!thread)
	{
		std::cerr << "Failed to locate valid thread\n";
		CloseHandle(snapshot);
		return false;
	}

	if (Wow64SuspendThread(thread) == static_cast<DWORD>(-1))
	{
		std::cerr << "Failed to suspend thread (" << GetLastError() << ")\n";
		std::cerr << "Thread ID: " << te32.th32ThreadID << '\n';
		CloseHandle(thread);
		return false;
	}

	//Getting thread context (GPR's only)
	WOW64_CONTEXT context { NULL };
	context.ContextFlags = WOW64_CONTEXT_CONTROL;
	if (!Wow64GetThreadContext(thread, &context))
	{
		std::cerr << "Failed to get thread context (" << GetLastError() << ")\n";
		goto exit;
	}

	// Pushing DllMain parameters & return address onto thread stack
	context.Esp -= 4; // LPVOID lpvReserved
	if (!wpm(context.Esp, &reserved, sizeof(LPVOID)))
	{
		std::cerr << "Failed to write lpvReserved to stack (" << GetLastError() << ")\n";
		std::cerr << "Address: " << HexOut << context.Esp << '\n';
		goto exit;
	}

	context.Esp -= 4; // DWORD fdwReason
	if (!wpm(context.Esp, &reason, sizeof(DWORD)))
	{
		std::cerr << "Failed to write fdwReason to stack (" << GetLastError() << ")\n";
		std::cerr << "Address: " << HexOut << context.Esp << '\n';
		goto exit;
	}

	context.Esp -= 4; // HINSTANCE hinstDLL
	if (!wpm(context.Esp, &modules[0].ImageBase, sizeof(HINSTANCE)))
	{
		std::cerr << "Failed to write hinstDLL to stack (" << GetLastError() << ")\n";
		std::cerr << "Address: " << HexOut << context.Esp << '\n';
		goto exit;
	}

	context.Esp -= 4; // Return address
	if (!wpm(context.Esp, &context.Eip, sizeof(DWORD)))
	{
		std::cerr << "Failed to write return address to stack (" << GetLastError() << ")\n";
		std::cerr << "Address: " << HexOut << context.Esp << '\n';
		goto exit;
	}

	context.Eip = modules[0].ImageBase + modules[0].image.NT_HEADERS->OptionalHeader.AddressOfEntryPoint;
	status = Wow64SetThreadContext(thread, &context);
	if (!status)
	{
		std::cerr << "Failed to set thread context (" << GetLastError() << ")\n";
		goto exit;
	}

exit:
	ResumeThread(thread);
	CloseHandle(thread);
	return status;
}