#pragma once

#include <string>
#include <unordered_map>

#include <windows.h>

#include <dbghelp.h>

namespace crashlogger::SymbolHelper {
// unordered_map<ModuleBase, <ModuleName, ModuleSize>>
inline std::unordered_map<DWORD64, std::pair<std::wstring, unsigned long>> moduleMap;

PSYMBOL_INFO GetSymbolInfo(HANDLE hProcess, DWORD64 address, DWORD64* displacement);
void         FreeSymbolInfo(PSYMBOL_INFO pSymbol);
bool         CreateModuleMap(HANDLE hProcess);
std::wstring MapModuleFromAddr(HANDLE hProcess, DWORD64 address);
std::wstring GetModuleVersionStr(HANDLE hProcess, HMODULE hModule);

} // namespace crashlogger::SymbolHelper
