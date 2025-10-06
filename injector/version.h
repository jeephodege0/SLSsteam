#ifndef VERSION_H
#define VERSION_H

// --- Version Numbers ---
// Use these to define the version of your application.
// These are the only numbers you should need to edit.

#define VERSION_MAJOR 1
#define VERSION_MINOR 0
#define VERSION_PATCH 0
#define VERSION_BUILD 0 // Often auto-incremented by a build server

// --- String Helpers ---
// These macros are used to convert the version numbers into strings
// for the resource file. You shouldn't need to change these.

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

// --- Resource File Defines ---
// These are the string and numeric representations of the version
// that will be used in the .rc file.

// Version for the resource file (e.g., 1,0,0,0)
#define VERSION_RC VERSION_MAJOR,VERSION_MINOR,VERSION_PATCH,VERSION_BUILD

// String version for the resource file (e.g., "1.0.0.0")
#define VERSION_STR STR(VERSION_MAJOR) "." STR(VERSION_MINOR) "." STR(VERSION_PATCH) "." STR(VERSION_BUILD)


// --- Product and File Information ---
// These strings are used in the "Details" tab of the file's properties dialog.
// Customize them for your application.

#define COMPANY_NAME_STR        "SuperSexySteam"
#define PRODUCT_NAME_STR        "Injector"
#define FILE_DESCRIPTION_STR    "Injects dll via LoadLibrary"
#define INTERNAL_NAME_STR       "Injector"
#define ORIGINAL_FILENAME_STR   "Injector.exe"
#define LEGAL_COPYRIGHT_STR     "Copyright (C) 2023 SuperSexySteam"


#endif // VERSION_H
