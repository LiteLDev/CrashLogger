#include "crashlogger/SymbolHelper.h"

#include <string>

#include "crashlogger/CrashLogger.h"

#include <Psapi.h>

using namespace std;
using crashlogger::Logger::pLogger;

namespace crashlogger::SymbolHelper {

PSYMBOL_INFO GetSymbolInfo(HANDLE hProcess, DWORD64 address, DWORD64* displacement) {
    auto pSymbol          = (PSYMBOL_INFO) new char[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen   = MAX_SYM_NAME;
    if (SymFromAddrW(hProcess, address, displacement, pSymbol))
        return pSymbol;
    else
        return nullptr;
}

void FreeSymbolInfo(PSYMBOL_INFO pSymbol) { delete[] ((char*)pSymbol); }

BOOL CALLBACK EnumerateModuleCallBack(
    PCTSTR                 ModuleName,
    DWORD64                ModuleBase,
    [[maybe_unused]] ULONG ModuleSize,
    [[maybe_unused]] PVOID UserContext
) {
    LPCWSTR name          = wcsrchr(ModuleName, TEXT('\\')) + 1;
    moduleMap[ModuleBase] = {name, ModuleSize};
    return TRUE;
}

bool CreateModuleMap(HANDLE hProcess) {
    if (!EnumerateLoadedModulesW64(hProcess, EnumerateModuleCallBack, nullptr)) {
        pLogger->error("Failed to enumerate loaded modules! Error Code: {}", GetLastError());
        return false;
    }
    return true;
}

wstring MapModuleFromAddr(HANDLE hProcess, DWORD64 address) { return moduleMap[SymGetModuleBase64(hProcess, address)].first; }

bool GetFileVersion(
    const wchar_t*  filePath,
    unsigned short* ver1,
    unsigned short* ver2,
    unsigned short* ver3,
    unsigned short* ver4,
    unsigned int*   flag = nullptr
) {

    DWORD dwHandle = 0;
    DWORD dwLen    = GetFileVersionInfoSizeW(filePath, &dwHandle);
    if (0 >= dwLen) {
        return false;
    }
    auto* pBlock = new (std::nothrow) wchar_t[dwLen];
    if (nullptr == pBlock) {
        return false;
    }
    if (!GetFileVersionInfoW(filePath, dwHandle, dwLen, pBlock)) {
        delete[] pBlock;
        return false;
    }

    VS_FIXEDFILEINFO* lpBuffer;
    unsigned int      uLen = 0;
    if (!VerQueryValueW(pBlock, L"\\", (void**)&lpBuffer, &uLen)) {
        delete[] pBlock;
        return false;
    }

    if (ver1)
        *ver1 = (lpBuffer->dwFileVersionMS >> 16) & 0x0000FFFF;
    if (ver2)
        *ver2 = lpBuffer->dwFileVersionMS & 0x0000FFFF;
    if (ver3)
        *ver3 = (lpBuffer->dwFileVersionLS >> 16) & 0x0000FFFF;
    if (ver4)
        *ver4 = lpBuffer->dwFileVersionLS & 0x0000FFFF;
    if (flag)
        *flag = lpBuffer->dwFileFlags;

    delete[] pBlock;
    return true;
}

inline std::wstring VersionToString(
    unsigned short major_ver,
    unsigned short minor_ver,
    unsigned short revision_ver,
    unsigned short build_ver,
    unsigned int   flag = 0
) {
    std::wstring flagStr;
    if (flag & VS_FF_DEBUG)
        flagStr += L" DEBUG";
    if (flag & VS_FF_PRERELEASE)
        flagStr += L" PRERELEASE";
    if (flag & VS_FF_PATCHED)
        flagStr += L" PATCHED";
    if (flag & VS_FF_PRIVATEBUILD)
        flagStr += L" PRIVATEBUILD";
    if (flag & VS_FF_INFOINFERRED)
        flagStr += L" INFOINFERRED";
    if (flag & VS_FF_SPECIALBUILD)
        flagStr += L" SPECIALBUILD";
    wchar_t buf[50];
    swprintf_s(buf, 50, L"%d.%d.%d.%d%ls", major_ver, minor_ver, revision_ver, build_ver, flagStr.c_str());
    return buf;
}

std::wstring GetModuleVersionStr(HANDLE hProcess, HMODULE hModule) {
    unsigned short major_ver, minor_ver, revision_ver, build_ver;
    unsigned int   flag;
    wchar_t        filePath[MAX_PATH] = {0};
    GetModuleFileNameEx(hProcess, hModule, filePath, MAX_PATH);
    if (GetFileVersion(filePath, &major_ver, &minor_ver, &revision_ver, &build_ver, &flag)) {
        return VersionToString(major_ver, minor_ver, revision_ver, build_ver, flag);
    }
    return {};
}

} // namespace crashlogger::SymbolHelper
