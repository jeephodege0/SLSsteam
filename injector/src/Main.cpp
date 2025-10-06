// Injector
#include "Injector.h"
#include "Seh.h"
#include "argh.h"
#include "StringUtil.h"
#include "UniUtil.h"

// Windows API
#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <Shlwapi.h>

// C++ Standard Library
#include <iostream>
#include <string>
#include <vector>
#include <locale>
#include <io.h>
#include <fcntl.h>

// Return values
#define RESULT_SUCCESS          0
#define RESULT_INVALID_COMMAND  1
#define RESULT_GENERAL_ERROR    2
#define RESULT_SEH_ERROR        3
#define RESULT_UNKNOWN_ERROR    4


// Entry point using wide characters for native Windows Unicode support
int wmain(int argc, wchar_t* argv[])
{
    // Set console output to UTF-16 to properly display wide characters
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    try
    {
        // Needed to proxy SEH exceptions to C++ exceptions
        SehGuard Guard;

        // Injector version number
        const std::wstring VerNum(L"20240218");

        // Version and copyright output
#ifdef _WIN64
        std::wcout << L"Injector x64 [Version " << VerNum << L"]" << std::endl;
#else
        std::wcout << L"Injector x86 [Version " << VerNum << L"]" << std::endl;
#endif
        std::wcout << L"Copyright (c) 2009 Cypher, 2012-2024 Nefarius. All rights reserved." << std::endl << std::endl;

        // The argh library uses char*, so we must convert our wide argv to UTF-8.
        std::vector<std::string> argv_utf8;
        argv_utf8.reserve(argc);
        for (int i = 0; i < argc; ++i)
        {
            argv_utf8.push_back(ConvertWideToUtf8(argv[i]));
        }
        std::vector<const char*> argv_utf8_c;
        argv_utf8_c.reserve(argc);
        for (const auto& arg : argv_utf8)
        {
            argv_utf8_c.push_back(arg.c_str());
        }
        
        argh::parser cmdl;
        cmdl.add_params({ "n", "process-name", "c", "case-sensitive", "w", "window-name", "p", "process-id" });
        cmdl.parse(static_cast<int>(argv_utf8_c.size()), argv_utf8_c.data());

        // Display help
        if (cmdl.pos_args().size() <= 1 || cmdl[{ "-h", "--help" }])
        {
            std::wcout << L"usage: Injector [options] [modules]" << std::endl << std::endl;
            std::wcout << L"  options:" << std::endl;
            std::wcout << L"    specify at least one of the following methods:" << std::endl;
            std::wcout << L"      -n, --process-name        Identify target process by process name" << std::endl;
            std::wcout << L"        -c, --case-sensitive    Make the target process name case-sensitive." << std::endl;
            std::wcout << L"                                Only applies when using -n or --process-name." << std::endl;
            std::wcout << L"      -w, --window-name         Identify target process by window title" << std::endl;
            std::wcout << L"      -p, --process-id          Identify target process by numeric ID" << std::endl << std::endl;
            std::wcout << L"    specify at least one of the following actions:" << std::endl;
            std::wcout << L"      -i, --inject              Inject/load referenced module" << std::endl;
            std::wcout << L"      -e, --eject               Eject/unload referenced module" << std::endl << std::endl;
            std::wcout << L"  modules:" << std::endl;
            std::wcout << L"      myLib.dll [anotherLib.dll] [C:\\hooks\\yetAnotherLib.dll]" << std::endl;
            std::wcout << std::endl;

            return RESULT_SUCCESS;
        }

        // Check if at least one action is specified
        if (!cmdl[{ "-i", "--inject", "-e", "--eject" }])
        {
            std::wcerr << L"No action specified!" << std::endl;
            return RESULT_INVALID_COMMAND;
        }

        // Check if user wants more than we can handle ;)
        if (cmdl[{ "-i", "--inject" }] && cmdl[{ "-e", "--eject" }])
        {
            std::wcerr << L"Only one action at a time allowed!" << std::endl;
            return RESULT_INVALID_COMMAND;
        }

        // Check if there's at least one process identification method specified
        if (!(cmdl({ "-n", "--process-name" }))
            && !(cmdl({ "-w", "--window-name" }))
            && !(cmdl({ "-p", "--process-id" })))
        {
            std::wcerr << L"No process identifier specified!" << std::endl;
            return RESULT_INVALID_COMMAND;
        }

        // Variable to store process ID
        DWORD ProcID = 0;
        
        // Find and inject via process name
        if (cmdl({ "-n", "--process-name" }))
        {
            std::string optArgUtf8 = cmdl({ "-n", "--process-name" }).str();
            if (!cmdl[{ "-c", "--case-sensitive" }])
                optArgUtf8 = toLower(optArgUtf8);

            // Attempt injection via process name
            ProcID = Injector::Get()->GetProcessIdByName(ConvertUtf8ToWide(optArgUtf8), cmdl[{ "-c", "--case-sensitive" }]);
        }

        // Find and inject via window name
        if (cmdl({ "-w", "--window-name" }))
        {
            std::string optArgUtf8 = cmdl({ "-w", "--window-name" }).str();
            // Attempt injection via window name
            ProcID = Injector::Get()->GetProcessIdByWindow(ConvertUtf8ToWide(optArgUtf8));
        }

        // Find and inject via process id
        if (cmdl({ "-p", "--process-id" }))
        {
            std::string optArgUtf8 = cmdl({ "-p", "--process-id" }).str();
            // Convert PID
            ProcID = _wtoi(ConvertUtf8ToWide(optArgUtf8).c_str());

            if (ProcID == 0)
            {
                throw std::runtime_error("Invalid PID entered!");
            }
        }

        // Get privileges required to perform the injection
        Injector::Get()->GetSeDebugPrivilege();

        std::vector<std::wstring> modules;
        for (auto it = std::next(cmdl.pos_args().begin()); it != cmdl.pos_args().end(); ++it)
            modules.push_back(ConvertUtf8ToWide(*it));

        // Inject action
        if (cmdl[{ "-i", "--inject" }])
        {
            for (auto& mod : modules)
            {
                std::wstring modulePath = PathIsRelativeW(mod.c_str())
                    ? Injector::Get()->GetPath(mod)
                    : mod;

                // Inject module
                Injector::Get()->InjectLib(ProcID, modulePath);
                // If we get to this point then no exceptions have been thrown so we
                // assume success.
                std::wcout << L"Successfully injected module!" << std::endl;
            }
        }

        // Eject action
        if (cmdl[{ "-e", "--eject" }])
        {
            for (auto& mod : modules)
            {
                std::wstring modulePath = PathIsRelativeW(mod.c_str())
                    ? Injector::Get()->GetPath(mod)
                    : mod;

                // Eject module
                Injector::Get()->EjectLib(ProcID, modulePath);
                // If we get to this point then no exceptions have been thrown so we
                // assume success.
                std::wcout << L"Successfully ejected module!" << std::endl;
            }
        }
    }
    // Catch C++ and SEH exceptions.
    catch (const std::exception& e)
    {
        // Convert the UTF-8 exception message to a wide string for console output.
        const std::wstring Error = ConvertUtf8ToWide(e.what());
        
        std::wcerr << L"Error:" << std::endl
            << Error << std::endl;

        // Check if the exception was our SEH proxy type
        if (dynamic_cast<const SehException*>(&e))
        {
            return RESULT_SEH_ERROR;
        }
        
        return RESULT_GENERAL_ERROR;
    }
    // Catch any other unknown exceptions.
    catch (...)
    {
        std::wcerr << L"Unknown error!" << std::endl;
        return RESULT_UNKNOWN_ERROR;
    }

    // Return success
    return RESULT_SUCCESS;
}