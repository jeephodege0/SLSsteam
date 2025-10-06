#pragma once

#include <Windows.h>
#include <eh.h>       // For _set_se_translator, _se_translator_function
#include <exception>  // For std::exception
#include <string>

// Function-local SEH guard. Proxies SEH to C++ EH
// Catch via SehException
class SehGuard
{
public:
	SehGuard();
	~SehGuard() noexcept;

	// This class manages a process-wide resource and must not be copied or moved.
	SehGuard(const SehGuard&) = delete;
	SehGuard& operator=(const SehGuard&) = delete;
	SehGuard(SehGuard&&) = delete;
	SehGuard& operator=(SehGuard&&) = delete;

private:
	_se_translator_function m_previousTranslator;
};

// SEH proxy exception.
// Catch this to catch structured exceptions as C++ exceptions.
// Must have an SehGuard object on the stack for this to work.
class SehException : public std::exception
{
public:
	SehException(unsigned int code, EXCEPTION_POINTERS* exceptionInfo);

	unsigned int GetCode() const noexcept;
	EXCEPTION_POINTERS* GetExceptionPointers() const noexcept;

	// Provides a descriptive message for the structured exception.
	const char* what() const noexcept override;

private:
	unsigned int m_code;
	EXCEPTION_POINTERS* m_exceptionInfo;
	mutable std::string m_whatMessage; // Holds the formatted message for what().
};

// The translator function that throws a C++ SehException.
extern void SehTranslatorFunction(unsigned int code, EXCEPTION_POINTERS* exceptionInfo);

// Generic unhandled exception filter, suitable for SetUnhandledExceptionFilter.
extern long __stdcall MyGenericUnhandledExceptionFilter(EXCEPTION_POINTERS* exceptionInfo);