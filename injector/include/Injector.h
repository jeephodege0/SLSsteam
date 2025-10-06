#pragma once

// Windows API
#include <Windows.h>

// C++ Standard Library
#include <string>

// Class to manage DLL injection into a remote process
class Injector
{
public:
	// Get singleton
	static Injector* Get();

	// Check if the library is injected.
	BYTE* GetModuleBaseAddress(HANDLE Process, const std::wstring& Path) const;
	BYTE* GetModuleBaseAddress(HANDLE Process, const std::string& Path) const;

	// Inject library
	bool InjectLib(DWORD ProcID, const std::wstring& Path) const;
	bool InjectLib(DWORD ProcID, const std::string& Path) const;

	// Eject library
	bool EjectLib(DWORD ProcID, const std::wstring& Path) const;
	bool EjectLib(DWORD ProcID, const std::string& Path) const;

	// Get fully qualified path from module name
	std::wstring GetPath(const std::wstring& ModuleName) const;

	// Get process id by name
	DWORD GetProcessIdByName(const std::wstring& Name, bool CompareCaseSensitive) const;
	// Get proces id by window
	DWORD GetProcessIdByWindow(const std::wstring& Name) const;

	// Get SeDebugPrivilege. Needed to inject properly.
	bool GetSeDebugPrivilege() const;

protected:
	// Enforce singleton
	Injector();
	~Injector();
	Injector(const Injector&);
	Injector& operator= (const Injector&);
private:
	// Singleton
	static Injector* m_pSingleton;

	//
	// Case-insensitive string comparison utility functions
	// 

	static bool icompare_pred(TCHAR a, TCHAR b);

	bool icompare(std::wstring const& a, std::wstring const& b) const;
};