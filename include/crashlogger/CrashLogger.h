#pragma once

#include "spdlog/spdlog.h"

#include "crashlogger/Logger.h"

#define CRASHLOGGER_VERSION "v1.0.0"

namespace crashlogger {

inline std::string BdsVersion;
inline bool        SilentMode = false;

} // namespace crashlogger
