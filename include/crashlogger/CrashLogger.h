#pragma once

#include "spdlog/spdlog.h"
#include <vector>

#include "crashlogger/Logger.h"

#define CRASHLOGGER_VERSION "v1.1.1"

namespace crashlogger {

inline std::string BdsVersion;
inline bool        SilentMode     = false;
inline bool        IsDev          = false;
inline bool        isEnableSentry = false;
inline std::string LeviVersion;
inline std::string UserName;
inline std::string ModDir;

} // namespace crashlogger
