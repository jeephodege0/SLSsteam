// StealthLib
#include "Seh.h"

// Windows API
#include <Windows.h>
#include <Dbghelp.h>
#include <eh.h>

// C++ Standard Library
#include <string>
#include <vector>
#include <sstream>

// Proxies SEH to C++ EH
void SehTranslatorFunction(unsigned int code, EXCEPTION_POINTERS* exceptionInfo)
{
	throw SehException(code, exceptionInfo);
}

// Constructor
SehGuard::SehGuard()
{
	m_previousTranslator = _set_se_translator(SehTranslatorFunction);
}

// Destructor
SehGuard::~SehGuard() noexcept
{
	_set_se_translator(m_previousTranslator);
}

// Proxy exception constructor
SehException::SehException(unsigned int code, EXCEPTION_POINTERS* exceptionInfo)
: m_code(code), m_exceptionInfo(exceptionInfo)
{ }

// Get exception code
unsigned int SehException::GetCode() const noexcept
{
	return m_code;
}

// Get exception data pointer
EXCEPTION_POINTERS* SehException::GetExceptionPointers() const noexcept
{
	return m_exceptionInfo;
}

// Provides a descriptive message for the structured exception.
const char* SehException::what() const noexcept
{
	if (m_whatMessage.empty()) {
		std::ostringstream oss;
		oss << "SEH Exception with code 0x" << std::hex << m_code;
		m_whatMessage = oss.str();
	}
	return m_whatMessage.c_str();
}

// Generic unhandled exception filter
LONG WINAPI MyGenericUnhandledExceptionFilter(EXCEPTION_POINTERS* ExceptionInfo)
{
	// Get the current time
	SYSTEMTIME sTime;
	GetLocalTime(&sTime);

	// Pull out the date
	std::vector<wchar_t> Date(10);
	GetDateFormatW(LOCALE_USER_DEFAULT, 0, &sTime, L"yyyyMMdd", &Date[0], 
		10);

	// Pull out the time
	std::vector<wchar_t> Time(10);
	GetTimeFormatW(LOCALE_USER_DEFAULT, TIME_FORCE24HOURFORMAT, &sTime, 
		L"hhmmss", &Time[0], 10);

	// Create a filename for the crash dump out of the current
	// date and time.
	std::wstring Path(L"Crash-");
	Path.append(&Date[0]).append(&Time[0]).append(L".dmp");

	// Create file to dump output
	HANDLE hFile = CreateFileW(Path.c_str(), GENERIC_WRITE, 0, NULL,
		CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		// Can't create a dump file, let the next handler (e.g., Windows Error Reporting) take over.
		return EXCEPTION_CONTINUE_SEARCH;
	}

	// Create minidump
	MINIDUMP_EXCEPTION_INFORMATION aMiniDumpInfo;
	aMiniDumpInfo.ThreadId = GetCurrentThreadId();
	aMiniDumpInfo.ExceptionPointers = ExceptionInfo;
	aMiniDumpInfo.ClientPointers = TRUE;

	// Write minidump
	MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile,
		(MINIDUMP_TYPE) (MiniDumpWithFullMemory|MiniDumpWithHandleData),
		&aMiniDumpInfo, NULL, NULL);

	// Close file handle
	CloseHandle(hFile);

	// Execute handler
	return EXCEPTION_EXECUTE_HANDLER;
}