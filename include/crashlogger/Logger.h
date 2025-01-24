#pragma once

#include <memory>

#include "spdlog/spdlog.h"
#include "crashlogger/StringUtils.h"

#include <unordered_set>
#include <windows.h>

#define MACHINE_TYPE                IMAGE_FILE_MACHINE_AMD64
#define CRASHLOGGER_LOG_DIR         "./logs/crash"
#define CRASHLOGGER_TRACE_PREFIX    "trace_"
#define CRASHLOGGER_MINIDUMP_PREFIX "minidump_"

namespace crashlogger::Logger {

inline std::string                     minidmpPath;
inline std::string                     tracePath;
inline std::string                     minidmpName;
inline std::string                     traceName;
inline std::unordered_set<std::string> suspectedModules;

inline std::shared_ptr<spdlog::logger> pLogger;

void LogCrash(PEXCEPTION_POINTERS e, HANDLE _hProcess, HANDLE _hThread, DWORD _dProcessId, DWORD _dThreadId);

// From https://github.com/LiteLDev/LeviLamina/blob/e4e0c8f3ba22050812980811e548f00931a7fc79/src/ll/api/base/CompilerPredefine.h

#define uint unsigned int

// MSVC has customized some functions and classes inside the compiler, but they are not included in IntelliSense. This
// header file is only used for IntelliSense.
#if defined(__INTELLISENSE__) || defined(__clang__) || defined(__clangd__)
// NOLINTBEGIN
#pragma pack(push, ehdata, 4)

typedef struct _PMD {
    int mdisp; // Offset of intended data within base
    int pdisp; // Displacement to virtual base pointer
    int vdisp; // Index within vbTable to offset of base
} _PMD;

typedef void (*_PMFN)(void);

#pragma pack(pop, ehdata)

#pragma warning(disable : 4200)
#pragma pack(push, _TypeDescriptor, 8)
typedef struct _TypeDescriptor {
    void const* pVFTable; // Field overloaded by RTTI
    void*       spare;    // reserved, possible for RTTI
    char        name[];   // The decorated name of the type; 0 terminated.
} _TypeDescriptor;
#pragma pack(pop, _TypeDescriptor)
#pragma warning(default : 4200)

typedef const struct _s__CatchableType {
    unsigned int     properties;       // Catchable Type properties (Bit field)
    _TypeDescriptor* pType;            // Image relative offset of TypeDescriptor
    _PMD             thisDisplacement; // Pointer to instance of catch type within thrown object.
    int   sizeOrOffset; // Size of simple-type object or offset into buffer of 'this' pointer for catch object
    _PMFN copyFunction; // Copy constructor or CC-closure
} _CatchableType;

#pragma warning(disable : 4200)
typedef const struct _s__CatchableTypeArray {
    int             nCatchableTypes;
    _CatchableType* arrayOfCatchableTypes[]; // Image relative offset of Catchable Types
} _CatchableTypeArray;
#pragma warning(default : 4200)

// NOLINTEND
#endif

// No one guarantees that the compiler's internal definitions are correct
#if !(defined(__INTELLISENSE__) || defined(__clangd__))
#pragma pack(push, 4)
struct CatchableType {
    uint properties;
    uint pType;
    _PMD thisDisplacement;
    uint sizeOrOffset;
    uint copyFunction;
};
struct ThrowInfo {
    uint attributes;
    uint pmfnUnwind;
    uint pForwardCompat;
    uint pCatchableTypeArray;
};
#pragma pack(pop)
#else
using CatchableType = ::_CatchableType;
using ThrowInfo     = ::_ThrowInfo;
#endif
} // namespace crashlogger::Logger
