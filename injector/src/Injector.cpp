// Windows Includes
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <malloc.h>

// C++ Standard Library
#include <vector>

// StealthLib
#include "Injector.h"
#include "EnsureCleanup.h"
#include "StringUtil.h"
#include "UniUtil.h"

// Static data
Injector* Injector::m_pSingleton = nullptr;

// Get injector singleton
Injector* Injector::Get()
{
	if (!m_pSingleton)
		m_pSingleton = new Injector();
	return m_pSingleton;
}

// Injector constructor
Injector::Injector()
{ }

// Note: This predicate is not used by the updated icompare function below.
bool Injector::icompare_pred(const wchar_t a, const wchar_t b)
{
	return std::tolower(a) == std::tolower(b);
}

// A robust, non-locale-dependent case-insensitive string comparison for Windows.
bool Injector::icompare(const std::wstring& a, const std::wstring& b) const
{
	return CSTR_EQUAL == CompareStringW(
		LOCALE_INVARIANT,
		NORM_IGNORECASE,
		a.c_str(),
		static_cast<int>(a.length()),
		b.c_str(),
		static_cast<int>(b.length())
	);
}

// Check if a module is injected via process handle, and return the base address
BYTE* Injector::GetModuleBaseAddress(HANDLE Process, const std::wstring& Path) const {
	// Grab a new snapshot of the process
	std::vector<HMODULE> Modules;
	DWORD SizeNeeded = 0;
	do
	{
		Modules.resize(SizeNeeded / sizeof(HMODULE));
		if (!EnumProcessModules(Process, Modules.data(), Modules.size() * sizeof(HMODULE), &SizeNeeded))
			throw std::runtime_error("Could not get module snapshot for remote process.");
	} while (SizeNeeded > Modules.size() * sizeof(HMODULE));

	// Get the HMODULE of the desired library
	bool Found = false;
	for (const auto &Module : Modules) 
	{
		WCHAR ModuleName[MAX_PATH];
		WCHAR ExePath[MAX_PATH];
		// The size of the ModuleName buffer, in characters.
		if (!GetModuleBaseNameW(Process, Module, ModuleName, sizeof(ModuleName) / sizeof(WCHAR)))
			throw std::runtime_error("Could not get ModuleName.");
		// The size of the ExePath buffer, in characters.
		if (!GetModuleFileNameExW(Process, Module, ExePath, sizeof(ExePath) / sizeof(WCHAR)))
			throw std::runtime_error("Could not get ExePath.");
		Found = (icompare(ModuleName, Path) || icompare(ExePath, Path));
		if (Found)
			return reinterpret_cast<BYTE*>(Module);
	}
	return nullptr;
}

// MBCS version of GetModuleBaseAddress
BYTE* Injector::GetModuleBaseAddress(HANDLE Process, const std::string& Path) const
{
	// Convert path from UTF-8 to unicode
	std::wstring UnicodePath = ConvertUtf8ToWide(Path);

	// Call the Unicode version of the function to actually do the work.
	return GetModuleBaseAddress(Process, UnicodePath);
}

// Injects a module (fully qualified path) via process id
bool Injector::InjectLib(DWORD ProcID, const std::wstring& Path) const
{
	// Get a handle for the target process.
	EnsureCloseHandle Process(OpenProcess(
		PROCESS_QUERY_INFORMATION |   // Required by Alpha
		PROCESS_VM_READ           |   // For EnumProcessModules
		PROCESS_CREATE_THREAD     |   // For CreateRemoteThread
		PROCESS_VM_OPERATION      |   // For VirtualAllocEx/VirtualFreeEx
		PROCESS_VM_WRITE,             // For WriteProcessMemory
		FALSE, ProcID));
	if (!Process) 
		throw std::runtime_error("Could not get handle to process.");

	// Calculate the number of bytes needed for the DLL's pathname
	size_t Size  = (Path.length() + 1) * sizeof(wchar_t);

	// Allocate space in the remote process for the pathname
	EnsureReleaseRegionEx LibFileRemote(VirtualAllocEx(Process, NULL, Size, MEM_COMMIT, PAGE_READWRITE),
		Process);
	if (!LibFileRemote)
		throw std::runtime_error("Could not allocate memory in remote process.");

	// Copy the DLL's pathname to the remote process' address space
	if (!WriteProcessMemory(Process, LibFileRemote, 
		Path.c_str(), Size, NULL))
		throw std::runtime_error("Could not write to memory in remote process.");;

	// Get the real address of LoadLibraryW in Kernel32.dll
	HMODULE hKernel32 = GetModuleHandleW(L"Kernel32");
	if (!hKernel32)
		throw std::runtime_error("Could not get handle to Kernel32.");
	PTHREAD_START_ROUTINE pfnThreadRtn = reinterpret_cast<PTHREAD_START_ROUTINE>
		(GetProcAddress(hKernel32, "LoadLibraryW"));
	if (!pfnThreadRtn)
		throw std::runtime_error("Could not get pointer to LoadLibraryW.");

	// Create a remote thread that calls LoadLibraryW(DLLPathname)
	EnsureCloseHandle Thread(CreateRemoteThread(Process, NULL, 0, pfnThreadRtn, 
		LibFileRemote, 0, NULL));
	if (!Thread)
		throw std::runtime_error("Could not create thread in remote process.");

	// Wait for the remote thread to terminate
	WaitForSingleObject(Thread, INFINITE);

	// it's possible that we get a thread exit code of 0 with a non-zero HMODULE,
	// as the thread exit code is a DWORD, which is smaller than an HMODULE - so,
	// check the process list.
	if (!GetModuleBaseAddress(Process, Path))
		throw std::runtime_error("Call to LoadLibraryW in remote process failed.");

	return true;
}

// MBCS version of InjectLib
bool Injector::InjectLib(DWORD ProcID, const std::string& Path) const
{
	// Convert path from UTF-8 to unicode
	std::wstring UnicodePath = ConvertUtf8ToWide(Path);

	// Call the Unicode version of the function to actually do the work.
	return InjectLib(ProcID, UnicodePath);
}

// Ejects a module (fully qualified path) via process id
bool Injector::EjectLib(DWORD ProcID, const std::wstring& Path) const
{
	// Get a handle for the target process.
	EnsureCloseHandle Process(OpenProcess(
		PROCESS_QUERY_INFORMATION |   
		PROCESS_VM_READ           |   
		PROCESS_CREATE_THREAD     | 
		PROCESS_VM_OPERATION,  // For CreateRemoteThread
		FALSE, ProcID));
	if (!Process) 
		throw std::runtime_error("Could not get handle to process.");

	const auto BaseAddress = GetModuleBaseAddress(Process, Path);
	if (!BaseAddress)
		throw std::runtime_error("Could not find module in remote process.");;

	// Get the real address of LoadLibraryW in Kernel32.dll
	HMODULE hKernel32 = GetModuleHandleW(L"Kernel32");
	if (hKernel32 == NULL) 
		throw std::runtime_error("Could not get handle to Kernel32.");
	PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)
		GetProcAddress(hKernel32, "FreeLibrary");
	if (pfnThreadRtn == NULL) 
		throw std::runtime_error("Could not get pointer to FreeLibrary.");

	// Create a remote thread that calls FreeLibrary()
	EnsureCloseHandle Thread(CreateRemoteThread(Process, NULL, 0, 
		pfnThreadRtn, BaseAddress, 0, NULL));
	if (!Thread) 
		throw std::runtime_error("Could not create thread in remote process.");

	// Wait for the remote thread to terminate
	WaitForSingleObject(Thread, INFINITE);

	// Get thread exit code
	DWORD ExitCode;
	if (!GetExitCodeThread(Thread,&ExitCode))
		throw std::runtime_error("Could not get thread exit code.");

	// Check LoadLibrary succeeded and returned a module base
	if(!ExitCode)
		throw std::runtime_error("Call to FreeLibrary in remote process failed.");

	return true;
}

// MBCS version of EjectLib
bool Injector::EjectLib(DWORD ProcID, const std::string& Path) const
{
	// Convert path from UTF-8 to unicode
	std::wstring UnicodePath = ConvertUtf8ToWide(Path);

	// Call the Unicode version of the function to actually do the work.
	return EjectLib(ProcID, UnicodePath);
}

// Gives the current process the SeDebugPrivilege so we can get the
// required process handle.
// Note: Requires administrator rights
bool Injector::GetSeDebugPrivilege() const
{
	// Open current process token with adjust rights
	HANDLE TempToken;
	BOOL RetVal = OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES
		| TOKEN_QUERY, &TempToken);
	if (!RetVal) 
		throw std::runtime_error("Could not open process token.");
	EnsureCloseHandle Token(TempToken);

	// Get the LUID for SE_DEBUG_NAME 
	LUID Luid = { NULL }; // Locally unique identifier
	if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Luid)) 
		throw std::runtime_error("Could not look up privilege value for SeDebugName.");
	if (Luid.LowPart == NULL && Luid.HighPart == NULL) 
		throw std::runtime_error("Could not get LUID for SeDebugName.");

	// Process privileges
	TOKEN_PRIVILEGES Privileges = { NULL };
	// Set the privileges we need
	Privileges.PrivilegeCount = 1;
	Privileges.Privileges[0].Luid = Luid;
	Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Apply the adjusted privileges
	if (!AdjustTokenPrivileges(Token, FALSE, &Privileges,
		sizeof (Privileges), NULL, NULL)) 
		throw std::runtime_error("Could not adjust token privileges.");

	return true;
}

// Get fully qualified path from module name. Assumes base directory is the
// directory of the currently executing binary.
std::wstring Injector::GetPath( const std::wstring& ModuleName ) const
{
	// Get handle to self
	HMODULE Self = GetModuleHandleW(NULL);

	// Get path to loader
	std::vector<wchar_t> LoaderPath(MAX_PATH);
	if (!GetModuleFileNameW(Self,&LoaderPath[0],static_cast<DWORD>(LoaderPath.size())) || 
		GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		throw std::runtime_error("Could not get path to loader.");

	// Convert path to loader to path to module
	std::wstring ModulePath(&LoaderPath[0]);
	ModulePath = ModulePath.substr(0, ModulePath.rfind( L"\\" ) + 1);
	ModulePath.append(ModuleName);

	wchar_t FullModulePath[MAX_PATH];
	if (!GetFullPathNameW(ModulePath.c_str(), sizeof(FullModulePath) / sizeof(wchar_t), FullModulePath, NULL))
		throw std::runtime_error("Could not get full path to module.");
	ModulePath = std::wstring(&FullModulePath[0]);

	// Check path/file is valid
	if (GetFileAttributesW(ModulePath.c_str()) == INVALID_FILE_ATTRIBUTES)
	{
		std::string NarrowModulePath(ConvertWideToUtf8(ModulePath));
		throw std::runtime_error("Could not find module. Path: '" + NarrowModulePath + "'.");
	}

	// Return module path
	return ModulePath;
}

// Get process ID via name
DWORD Injector::GetProcessIdByName(const std::wstring& Name, const bool CompareCaseSensitive) const
{
	// Grab a new snapshot of the process
	EnsureCloseHandle Snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));
	if (Snap == INVALID_HANDLE_VALUE)
		throw std::runtime_error("Could not get process snapshot.");

	// Search for process
	PROCESSENTRY32W ProcEntry = { };
    ProcEntry.dwSize = sizeof(ProcEntry);
	bool Found = false;
	BOOL MoreMods = Process32FirstW(Snap, &ProcEntry);
	for (; MoreMods; MoreMods = Process32NextW(Snap, &ProcEntry)) 
	{
		std::wstring CurrentProcess(ProcEntry.szExeFile);

		if (CompareCaseSensitive)
		{
			Found = (CurrentProcess == Name);
		}
		else
		{
			Found = icompare(CurrentProcess, Name);
		}
		
		if (Found) break;
	}

	// Check process was found
	if (!Found)
		throw std::runtime_error("Could not find process.");

	// Return PID
	return ProcEntry.th32ProcessID;
}

// Get process id from window name
DWORD Injector::GetProcessIdByWindow(const std::wstring& Name) const
{
	// Find window
	HWND MyWnd = FindWindowW(NULL,Name.c_str());
	if (!MyWnd)
		throw std::runtime_error("Could not find window.");

	// Get process ID from window
	DWORD ProcID;
	GetWindowThreadProcessId(MyWnd,&ProcID);
	if (!ProcID)
		throw std::runtime_error("Could not get process id from window.");

	// Return process id
	return ProcID;
}