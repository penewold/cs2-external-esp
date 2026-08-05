#include "IMemory.hpp"
#include <Psapi.h> 
#include <TlHelp32.h>

typedef NTSTATUS(WINAPI* pNtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead);
typedef NTSTATUS(WINAPI* pNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

class pMemory {

public:
	pMemory() {
		pfnNtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
		pfnNtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	}

	pNtReadVirtualMemory pfnNtReadVirtualMemory;
	pNtWriteVirtualMemory pfnNtWriteVirtualMemory;
};

HANDLE		  handle_; // handle to process
HWND		  hwnd_; // window handle

HWND GetWindowHandleFromProcessId(DWORD process_id) {
	HWND hwnd = NULL;
	do {
		hwnd = FindWindowEx(NULL, hwnd, NULL, NULL);
		DWORD pid = 0;
		GetWindowThreadProcessId(hwnd, &pid);
		if (pid == process_id) {
			TCHAR windowTitle[MAX_PATH];
			GetWindowText(hwnd, windowTitle, MAX_PATH);
			if (IsWindowVisible(hwnd) && windowTitle[0] != '\0') {
				return hwnd;
			}
		}
	} while (hwnd != NULL);
	return NULL; // No main window found for the given process ID
}

bool pProcess::IsValid() {
	return handle_ != NULL;
}

std::vector<MemoryRegion> pProcess::GetMemoryRegions(ProcessModule module) {
	uintptr_t start = module.base;
	uintptr_t end = module.base + module.size;

	std::vector<MemoryRegion> regions;

	MEMORY_BASIC_INFORMATION mbi;
	while (start < end && 
		VirtualQueryEx(handle_,
		reinterpret_cast<LPCVOID>(start),
		&mbi,
		sizeof(mbi)) != 0)
	{
		regions.push_back({
			reinterpret_cast<uintptr_t>(mbi.BaseAddress),
			reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize,
			mbi.RegionSize
		});

		start = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
	}

	return regions;
}

uint32_t pProcess::FindProcessIdByProcessName(const char* process_name)
{
	std::wstring wideProcessName;
	int wideCharLength = MultiByteToWideChar(CP_UTF8, 0, process_name, -1, nullptr, 0);
	if (wideCharLength > 0)
	{
		wideProcessName.resize(wideCharLength);
		MultiByteToWideChar(CP_UTF8, 0, process_name, -1, &wideProcessName[0], wideCharLength);
	}

	HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32W process_entry_{ };
	process_entry_.dwSize = sizeof(PROCESSENTRY32W);

	DWORD pid = 0;
	if (Process32FirstW(hPID, &process_entry_))
	{
		do
		{
			if (!wcscmp(process_entry_.szExeFile, wideProcessName.c_str()))
			{
				pid = process_entry_.th32ProcessID;
				break;
			}
		} while (Process32NextW(hPID, &process_entry_));
	}
	CloseHandle(hPID);
	return pid;
}

uint32_t pProcess::FindProcessIdByWindowName(const char* window_name)
{
	DWORD process_id = 0;
	HWND windowHandle = FindWindowA(nullptr, window_name);
	if (windowHandle)
		GetWindowThreadProcessId(windowHandle, &process_id);
	return process_id;
}

bool pProcess::read_raw(uintptr_t address, void* buffer, size_t size) {
	SIZE_T bytesRead;
	pMemory cMemory;

	NTSTATUS status = cMemory.pfnNtReadVirtualMemory(handle_, (PVOID)(address), buffer, static_cast<ULONG>(size), (PULONG)&bytesRead);

	return status == 0x00000000/*STATUS_SUCCESS*/ || bytesRead == size;
}

size_t pProcess::read_impl(uintptr_t address, void* buffer, size_t size)
{
	pMemory cMemory;
	ULONG bytesRead;

	cMemory.pfnNtReadVirtualMemory(handle_, reinterpret_cast<void*>(address), buffer, size, &bytesRead);
	return static_cast<size_t>(bytesRead);
}

size_t pProcess::write_impl(uintptr_t address, const void* value, size_t size)
{
	pMemory cMemory;
	ULONG bytesWritten;

	cMemory.pfnNtWriteVirtualMemory(handle_, reinterpret_cast<void*>(address), &value, size, &bytesWritten);
	return bytesWritten;
}

bool pProcess::AttachProcess(std::string process_name)
{
	process_name.append(".exe");

	this->pid_ = this->FindProcessIdByProcessName(process_name.c_str());

	if (pid_)
	{
		HMODULE modules[0xFF];
		MODULEINFO module_info;
		DWORD _;

		handle_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
			PROCESS_VM_READ, FALSE, pid_);

		if (!handle_)
			return false;

		EnumProcessModulesEx(handle_, modules, sizeof(modules), &_, LIST_MODULES_64BIT);
		base_client_.base = (uintptr_t)modules[0];

		GetModuleInformation(handle_, modules[0], &module_info, sizeof(module_info));
		base_client_.size = module_info.SizeOfImage;

		hwnd_ = GetWindowHandleFromProcessId(pid_);

		return true;
	}

	return false;
}

void pProcess::Close()
{
	CloseHandle(handle_);
}

ProcessModule pProcess::GetModule(std::string module_name)
{
	module_name.append(".dll");

	std::wstring wideModule;
	int wideCharLength = MultiByteToWideChar(CP_UTF8, 0, module_name.c_str(), -1, nullptr, 0);
	if (wideCharLength > 0)
	{
		wideModule.resize(wideCharLength);
		MultiByteToWideChar(CP_UTF8, 0, module_name.c_str(), -1, &wideModule[0], wideCharLength);
	}

	HANDLE handle_module = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid_);
	MODULEENTRY32W module_entry_{};
	module_entry_.dwSize = sizeof(MODULEENTRY32W);

	do
	{
		if (!wcscmp(module_entry_.szModule, wideModule.c_str()))
		{
			CloseHandle(handle_module);
			return { (DWORD_PTR)module_entry_.modBaseAddr, module_entry_.dwSize };
		}
	} while (Module32NextW(handle_module, &module_entry_));

	CloseHandle(handle_module);
	return { 0, 0 };
}
