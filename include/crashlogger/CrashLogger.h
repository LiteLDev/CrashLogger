#pragma once

#include "spdlog/spdlog.h"

#include "crashlogger/Logger.h"

#define CRASHLOGGER_VERSION "v1.1.1"

namespace crashlogger {

inline std::string BdsVersion;
inline bool        SilentMode = false;

} // namespace crashlogger
