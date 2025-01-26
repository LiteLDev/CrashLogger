#pragma once

#include <filesystem>
#include <string>
#include <vector>


namespace crashlogger::ModHelper {
struct ModInfo {
    std::string name;
    std::string dsn;
    std::string version;
    bool        inSuspectedModule;
};
inline std::vector<ModInfo> pendingMods;

void parseModSentryInfo(const std::filesystem::path& modPath);
} // namespace crashlogger::ModHelper