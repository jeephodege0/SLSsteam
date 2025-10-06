# =============================================================================
# Project Definition
# =============================================================================
cmake_minimum_required(VERSION 3.16)
project(Injector LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# =============================================================================
# Project Configuration
# =============================================================================
# --- OUTPUT DIRECTORY ---
# Place all binaries directly in the build directory (e.g., build/Debug/Injector.exe)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}") 
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}") 

# --- MSVC Runtime ---
# Set the MSVC runtime library to static multithreaded (/MT) for all configurations.
# This avoids dependencies on the Visual C++ Redistributable.
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()

# =============================================================================
# Define Executable Target
# =============================================================================
# Define all source files.
set(PROJECT_SOURCES
    src/Main.cpp
    src/Injector.cpp
    src/Seh.cpp
    resource.rc
)

# Define all header files.
set(PROJECT_HEADERS
    include/argh.h
    include/EnsureCleanup.h
    include/Injector.h
    include/Seh.h
    include/StringUtil.h
    include/UniUtil.h
    version.h
)

# Pass all files to the target.
add_executable(Injector ${PROJECT_SOURCES} ${PROJECT_HEADERS})

# =============================================================================
# Target Properties & Dependencies
# =============================================================================
# --- Headers ---
# Ensure the current source directory is in the include path
target_include_directories(Injector PRIVATE 
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

# --- Preprocessor Definitions ---
target_compile_definitions(Injector PRIVATE
    # Common definitions for all build types
    STATIC_GETOPT
    UNICODE
    _UNICODE
    WIN32
    _CONSOLE

    # Release-specific definitions
    $<$<CONFIG:Release>:NDEBUG>
)

# --- Compiler Options ---
target_compile_options(Injector PRIVATE
    # Common options for MSVC
    /W4     # Warning level 4
    /WX     # Treat warnings as errors
    /EHa    # Enable SEH exception handling
    /GF     # Enable string pooling

    # Debug options
    $<$<CONFIG:Debug>:/Od /Zi>

    # Release options
    $<$<CONFIG:Release>:/O2 /Ob2 /Oi /Ot /Oy /GT>
)

# Enable Interprocedural Optimization (Link-Time Code Generation) for Release builds.
set_property(TARGET Injector PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)

# --- Link Dependencies & Options ---
# System libraries required by the project.
target_link_libraries(Injector PRIVATE
    DbgHelp
    shlwapi
)

# Linker options.
target_link_options(Injector PRIVATE
    "/ENTRY:wmainCRTStartup"

    # Common linker options
    "/MANIFESTUAC:level='asInvoker' uiAccess='false'" # UAC settings
    /OPT:REF                                          # Eliminate unreferenced functions/data
    /OPT:ICF                                          # Perform identical COMDAT folding

    # Debug options
    $<$<CONFIG:Debug>:/INCREMENTAL:NO /DEBUG>

    # Release options
    $<$<CONFIG:Release>:/INCREMENTAL:NO /DEBUG:NONE>
)

# =============================================================================
# Final User Messages
# =============================================================================
message(STATUS "Project 'Injector' configured successfully.")