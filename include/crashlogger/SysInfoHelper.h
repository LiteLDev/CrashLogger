#pragma once

#include <string>

namespace crashlogger::SysInfoHelper {

std::string GetSystemVersion();

std::string GetProcessorName();

std::string GetProcessorArchitecture();

uint64_t GetTotalPhysicalMemory();

uint64_t GetAvailablePhysicalMemory();

uint32_t GetProcessorCount();

bool IsWine();

} // namespace crashlogger::SysInfoHelper
