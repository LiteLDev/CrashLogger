#include "crashlogger/SysInfoHelper.h"

#include "crashlogger/StringUtils.h"

#include <windows.h>

#include <intrin.h>

#define STATUS_SUCCESS (0x00000000)
typedef LONG NTSTATUS, *PNTSTATUS;

using crashlogger::StringUtils::w2u8;

namespace crashlogger::SysInfoHelper {

typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

RTL_OSVERSIONINFOW GetRealOSVersion() {
    RTL_OSVERSIONINFOW osVersionInfoW = {0};

    HMODULE hMod = ::GetModuleHandleW(L"ntdll.dll");
    if (hMod) {
        auto fxPtr = (RtlGetVersionPtr)::GetProcAddress(hMod, "RtlGetVersion");
        if (fxPtr != nullptr) {
            osVersionInfoW.dwOSVersionInfoSize = sizeof(osVersionInfoW);
            if (STATUS_SUCCESS == fxPtr(&osVersionInfoW)) {
                return osVersionInfoW;
            }
        }
    }
    return osVersionInfoW;
}

std::string GetSystemVersion() {
    RTL_OSVERSIONINFOW osVersionInfoW = GetRealOSVersion();
    if (osVersionInfoW.dwMajorVersion == 0) {
        return "Unknown";
    }
    std::string osVersion =
        std::to_string(osVersionInfoW.dwMajorVersion) + "." + std::to_string(osVersionInfoW.dwMinorVersion);
    if (osVersionInfoW.dwBuildNumber != 0) {
        osVersion += "." + std::to_string(osVersionInfoW.dwBuildNumber);
    }
    if (osVersionInfoW.szCSDVersion[0] != 0) {
        osVersion += " " + std::string(w2u8(osVersionInfoW.szCSDVersion));
    }
    return osVersion;
}

std::string GetProcessorName() {
    int cpuInfo[4] = {-1};
    __cpuid(cpuInfo, (int)0x80000000);
    unsigned int nExIds = cpuInfo[0];

    char cpuBrandString[0x40] = {0};
    for (unsigned int i = 0x80000000; i <= nExIds; ++i) {
        __cpuid(cpuInfo, i);
        if (i == 0x80000002) {
            memcpy(cpuBrandString, cpuInfo, sizeof(cpuInfo));
        } else if (i == 0x80000003) {
            memcpy(cpuBrandString + 16, cpuInfo, sizeof(cpuInfo));
        } else if (i == 0x80000004) {
            memcpy(cpuBrandString + 32, cpuInfo, sizeof(cpuInfo));
        }
    }
    return cpuBrandString;
}

std::string GetProcessorArchitecture() {
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    switch (systemInfo.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        return "x64";
    case PROCESSOR_ARCHITECTURE_ARM:
        return "ARM";
    case PROCESSOR_ARCHITECTURE_ARM64:
        return "ARM64";
    case PROCESSOR_ARCHITECTURE_IA64:
        return "IA64";
    case PROCESSOR_ARCHITECTURE_INTEL:
        return "x86";
    case PROCESSOR_ARCHITECTURE_UNKNOWN:
    default:
        return "Unknown";
    }
}

uint32_t GetProcessorCount() {
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    return systemInfo.dwNumberOfProcessors;
}

uint64_t GetTotalPhysicalMemory() {
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    return memoryStatus.ullTotalPhys;
}

bool IsWine() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == nullptr) {
        return false;
    }
    return GetProcAddress(hNtdll, "wine_get_version") != nullptr;
}

} // namespace crashlogger::SysInfoHelper
