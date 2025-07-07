#include <cpr/cpr.h>
#include <fstream>
#include <iostream>
#include <objbase.h>
#include <random>
#include <sstream>

#include <zlib.h>

#include "crashlogger/CrashLogger.h"
#include "crashlogger/ModHelper.h"
#include "crashlogger/SentryUploader.h"
#include "crashlogger/SysInfoHelper.h"


using json = nlohmann::json;
using namespace crashlogger;
using namespace crashlogger::Logger;

extern std::shared_ptr<spdlog::logger> pCombinedLogger;

namespace crashLogger {

std::string compressDataGzip(const std::string& data) {
    std::vector<char> compressedBuffer;
    z_stream          deflateStream{};
    if (deflateInit2(&deflateStream, Z_BEST_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        throw std::runtime_error("Failed to initialize compression stream");
    }
    if (data.size() > std::numeric_limits<uInt>::max()) {
        deflateEnd(&deflateStream);
        throw std::runtime_error("Data too large for compression");
    }
    deflateStream.avail_in = static_cast<uInt>(data.size());
    deflateStream.next_in  = (Bytef*)data.data();
    size_t bufferSize      = data.size();
    compressedBuffer.resize(bufferSize);
    deflateStream.avail_out = static_cast<uInt>(bufferSize);
    deflateStream.next_out  = (Bytef*)compressedBuffer.data();
    if (deflate(&deflateStream, Z_FINISH) != Z_STREAM_END) {
        deflateEnd(&deflateStream);
        throw std::runtime_error("Gzip compression failed");
    }
    compressedBuffer.resize(deflateStream.total_out);
    deflateEnd(&deflateStream);
    return {compressedBuffer.begin(), compressedBuffer.end()};
}

std::string generateUUID() {
    thread_local static std::mt19937_64 rng(std::random_device{}());
    std::array<unsigned char, 16>       bytes{};
    uint64_t                            random_part1 = rng();
    uint64_t                            random_part2 = rng();

    static_assert(sizeof(uint64_t) == 8, "Unexpected size");
    std::memcpy(bytes.data(), &random_part1, 8);
    std::memcpy(bytes.data() + 8, &random_part2, 8);
    bytes[6]               = (unsigned char)((bytes[6] & 0x0F) | 0x40);
    bytes[8]               = (unsigned char)((bytes[8] & 0x3F) | 0x80);
    static const char* hex = "0123456789abcdef";
    std::string        uuid;
    uuid.reserve(36);

    for (size_t i = 0; i < 16; ++i) {
        uuid.push_back(hex[(bytes[i] >> 4) & 0x0F]);
        uuid.push_back(hex[bytes[i] & 0x0F]);
        if (i == 3 || i == 5 || i == 7 || i == 9) {
            uuid.push_back('-');
        }
    }
    return uuid;
}

SentryUploader::SentryUploader(
    const std::string& user,
    const std::string& minidmpName,
    const std::string& minidumpPath,
    const std::string& traceName,
    const std::string& tracePath,
    bool               isDev,
    const std::string& leviLaminaVersion
)
: mUser(user),
  mMiniDumpName(minidmpName),
  mMinidumpPath(minidumpPath),
  mTraceName(traceName),
  mTracePath(tracePath),
  mIsDev(isDev),
  mLeviLaminaVersion(leviLaminaVersion) {
    mMinidumpContent       = readFile(minidumpPath);
    mAdditionalFileContent = readFile(tracePath);
    mOSInfo.name           = SysInfoHelper::IsWine() ? "Linux(Wine)" : "Windows";
    mOSInfo.version        = SysInfoHelper::GetSystemVersion();
    ModHelper::parseModSentryInfo(crashlogger::ModDir);
}

void SentryUploader::addModSentryInfo(
    const std::string& modName,
    const std::string& dsn,
    const std::string& releaseVersion,
    bool               isInSuspectedModules
) {
    try {
        auto protocolEnd = dsn.find("://");
        auto authEnd     = dsn.find('@', protocolEnd + 3);
        auto lastSlash   = dsn.rfind('/');

        if (protocolEnd == std::string::npos || authEnd == std::string::npos || lastSlash == std::string::npos) {
            throw std::invalid_argument("Invalid DSN format");
        }

        SentryInfo::DSNInfo info;
        info.protocol  = dsn.substr(0, protocolEnd);
        auto auth      = dsn.substr(protocolEnd + 3, authEnd - protocolEnd - 3);
        info.publicKey = auth.substr(0, auth.find(':'));
        info.host      = dsn.substr(authEnd + 1, lastSlash - authEnd - 1);
        info.projectId = dsn.substr(lastSlash + 1);

        mModsSentryConfig.push_back({info, dsn, modName, releaseVersion, isInSuspectedModules});
    } catch (const std::exception& e) {
        pCombinedLogger->error("Error adding mod sentry info: {}", e.what());
        return;
    }
}

void SentryUploader::uploadAll() {
    std::vector<std::thread> threads;

    threads.reserve(mModsSentryConfig.size());
    pCombinedLogger->info("");
    pCombinedLogger->info("Uploading crash report to Sentry...");
    for (const auto& sentryConfig : mModsSentryConfig) {
        threads.emplace_back([=, this]() {
            try {
                std::string url = sentryConfig.dsnInfo.protocol + "://" + sentryConfig.dsnInfo.host + "/api/" +
                                  sentryConfig.dsnInfo.projectId + "/envelope/";
                std::string eventId = generateUUID();

                json envelopeHeader = {
                    {"event_id", eventId         },
                    {"dsn",      sentryConfig.dsn}
                };

                json eventPayload = {
                    {"event_id",    eventId                                                                       },
                    {"level",       sentryConfig.isFatal ? "fatal" : "warning"                                    },
                    {"platform",    "native"                                                                      },
                    {"sdk",         {{"name", "crashLogger"}, {"version", CRASHLOGGER_VERSION}}                   },
                    {"release",     sentryConfig.releaseVersion                                                   },
                    {"environment", mIsDev ? "development" : "production"                                         },
                    {"user",        {{"id", mUser}}                                                               },
                    {"contexts",
                     {{"os", {{"name", mOSInfo.name}, {"version", mOSInfo.version}}},
                      {"runtime", {{"type", "runtime"}, {"name", "LeviLamina"}, {"version", mLeviLaminaVersion}}}}},
                };

                sendToSentry(sentryConfig, url, envelopeHeader, eventPayload);
            } catch (const std::exception& e) {
                pCombinedLogger->error("Error uploading to DSN: {}, Error: {}", sentryConfig.dsn, e.what());
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }
}

std::string SentryUploader::readFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filePath);
    }
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

void SentryUploader::sendToSentry(
    const SentryInfo&     sentryInfo,
    const std::string&    url,
    const nlohmann::json& envelopeHeader,
    const nlohmann::json& eventPayload
) {
    json eventHeader = {
        {"type",   "event"                                     },
        {"length", static_cast<int>(eventPayload.dump().size())}
    };

    json minidumpItemHeader = {
        {"type",            "attachment"                             },
        {"length",          static_cast<int>(mMinidumpContent.size())},
        {"filename",        mMiniDumpName                            },
        {"attachment_type", "event.minidump"                         }
    };

    json traceFileItemHeader = {
        {"type",            "attachment"                                   },
        {"length",          static_cast<int>(mAdditionalFileContent.size())},
        {"filename",        mTraceName                                     },
        {"attachment_type", "event.attachment"                             }
    };

    std::ostringstream envelopeStream;

    envelopeStream << envelopeHeader.dump() << "\n"
                   << eventHeader.dump() << "\n"
                   << eventPayload.dump() << "\n"
                   << minidumpItemHeader.dump() << "\n"
                   << mMinidumpContent << "\n"
                   << traceFileItemHeader.dump() << "\n"
                   << mAdditionalFileContent << "\n";

    std::string compressedData = compressDataGzip(envelopeStream.str());

    auto response = cpr::Post(
        cpr::Url{
            url
    },
        cpr::Header{
            {"Content-Type", "application/x-sentry-envelope"},
            {"Content-Encoding", "gzip"},
            {"X-Sentry-Auth",
             "Sentry sentry_version=7,sentry_client=sentry.dofes/0.1,sentry_key=" + sentryInfo.dsnInfo.publicKey},
        },
        cpr::Body{compressedData}
    );

    if (response.status_code == 200) {
        pCombinedLogger->info("Mod: {} uploaded successfully to Sentry", sentryInfo.modName);
        pCombinedLogger->info("Event ID: {}", json::parse(response.text)["id"]);
    } else {
        pCombinedLogger->error("Mod: {} Failed to upload to Sentry", sentryInfo.modName);
        pCombinedLogger->error("Status Code: {}", response.status_code);
        pCombinedLogger->error("Response: {}", response.text);
    }
}
} // namespace crashLogger