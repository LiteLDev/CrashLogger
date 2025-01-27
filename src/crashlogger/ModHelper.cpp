#include "crashlogger/ModHelper.h"
#include "crashlogger/CrashLogger.h"
#include "crashlogger/Logger.h"
#include "nlohmann/json.hpp"
#include <fstream>
#include <iostream>

using namespace crashlogger::Logger;

namespace crashlogger::ModHelper {

void parseModSentryInfo(const std::filesystem::path& modPath) {
    for (const auto& entry : std::filesystem::directory_iterator(modPath)) {
        if (!entry.is_directory())
            continue;

        auto manifestPath = entry.path() / "manifest.json";
        if (!std::filesystem::exists(manifestPath))
            continue;

        std::ifstream manifestFile(manifestPath);
        if (!manifestFile.is_open())
            continue;

        nlohmann::json manifestJson;
        manifestFile >> manifestJson;
        std::string dsn = manifestJson.value("sentry-dsn", "");
        if (dsn.empty())
            continue;

        std::string moduleEntry = manifestJson.value("entry", "");
        bool        forceUpload = manifestJson.value("sentry-force-upload", false);

        bool isInSuspectedModules = (suspectedModules.find(moduleEntry) != suspectedModules.end());
        if (!isInSuspectedModules && !forceUpload)
            continue;

        std::string name    = manifestJson.value("name", "");
        std::string version = manifestJson.value("version", "");
        pendingMods.emplace_back(name, dsn, version, isInSuspectedModules);
    }
}

} // namespace crashlogger::ModHelper