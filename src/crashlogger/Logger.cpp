#include <filesystem>
#include <map>
#include <queue>
#include <string>
#include <system_error>
#include <unordered_set>

#include "Zydis/Decoder.h"
#include "Zydis/Formatter.h"
#include "fmt/chrono.h"
#include "spdlog/logger.h"
#include "spdlog/sinks/basic_file_sink.h"

#include "crashlogger/CrashLogger.h"
#include "crashlogger/Logger.h"
#include "crashlogger/ModHelper.h"
#include "crashlogger/SentryUploader.h"
#include "crashlogger/StringUtils.h"
#include "crashlogger/SymbolHelper.h"
#include "crashlogger/SysInfoHelper.h"


#include <windows.h>

#include <Psapi.h>

std::shared_ptr<spdlog::logger> pCombinedLogger;

struct HandleCloser {
    HANDLE h;
    explicit HandleCloser(HANDLE h) : h(h) {}
    ~HandleCloser() { CloseHandle(h); }
};

namespace crashlogger::Logger {

HANDLE hProcess;
HANDLE hThread;
DWORD  dwProcessId;
DWORD  dwThreadId;

std::filesystem::path targetDirPath;
std::filesystem::path targetExePath;
std::filesystem::path logDirPath;

std::string date;

bool InitFileLogger() {
    using namespace std;
    using namespace std::filesystem;
    string logFileName = CRASHLOGGER_TRACE_PREFIX + date + ".log";
    path   logFilePath = logDirPath / logFileName;
    try {
        auto fileLoggerSink = make_shared<spdlog::sinks::basic_file_sink_mt>(logFilePath.string(), true);
        fileLoggerSink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
        pCombinedLogger =
            make_shared<spdlog::logger>("combined", spdlog::sinks_init_list{pLogger->sinks().front(), fileLoggerSink});
    } catch (spdlog::spdlog_ex& ex) {
        pLogger->error("Failed to create file logger! Error: {}", ex.what());
        return false;
    }

    traceName = logFileName;
    tracePath = logFilePath.string();
    return true;
}

bool GenerateMiniDumpFile(PEXCEPTION_POINTERS e) {
    using namespace std;
    using namespace std::filesystem;
    using namespace crashlogger::StringUtils;

    string dumpFileName = CRASHLOGGER_MINIDUMP_PREFIX + date + ".dmp";
    path   dumpFilePath = logDirPath / dumpFileName;

    auto hDumpFile = CreateFileW(
        dumpFilePath.native().c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (hDumpFile == INVALID_HANDLE_VALUE || hDumpFile == nullptr) {
        pLogger->error("Failed to create MiniDump file! Error Code: 0x{:X}", GetLastError());
        return false;
    }
    HandleCloser hDumpFileCloser(hDumpFile);

    MINIDUMP_EXCEPTION_INFORMATION dumpInfo;
    ZeroMemory(&dumpInfo, sizeof(MINIDUMP_EXCEPTION_INFORMATION));

    dumpInfo.ExceptionPointers = e;
    dumpInfo.ThreadId          = dwThreadId;
    dumpInfo.ClientPointers    = FALSE;

    if (!MiniDumpWriteDump(hProcess, dwProcessId, hDumpFile, MiniDumpNormal, &dumpInfo, nullptr, nullptr)) {
        pLogger->error("Failed to generate MiniDump! Error Code: 0x{:X}", GetLastError());
        return false;
    }

    if (!FlushFileBuffers(hDumpFile)) {
        pLogger->error("Failed to flush buffers to disk! Error Code: 0x{:X}", GetLastError());
        return false;
    }

    CloseHandle(hDumpFile);

    error_code ec;
    dumpFilePath = canonical(dumpFilePath, ec);
    if (ec) {
        pLogger->error("Failed to canonicalize MiniDump path! Error Code: 0x{:X}", ec.value());
        return false;
    }
    string path = w2u8(dumpFilePath.native());

    minidmpName = dumpFileName;
    minidmpPath = path;
    pLogger->info("MiniDump generated at {}", path);
    return true;
}

void DumpSystemInfo() {
    using namespace crashlogger;
    auto now = std::chrono::system_clock::now();

    pCombinedLogger->info("System Info: ");
    pCombinedLogger->info("  OS Version: {}", SysInfoHelper::GetSystemVersion());
    pCombinedLogger->info("  Is Wine: {}", SysInfoHelper::IsWine());
    pCombinedLogger->info("  CPU: {}", SysInfoHelper::GetProcessorName());
    pCombinedLogger->info("  CPU Counts: {}", SysInfoHelper::GetProcessorCount());
    pCombinedLogger->info("  CPU Arch: {}", SysInfoHelper::GetProcessorArchitecture());
    pCombinedLogger->info("  RAM: {} MB", SysInfoHelper::GetTotalPhysicalMemory() / 1024 / 1024);
    pCombinedLogger->info("  Time: {}", fmt::format("{:%Y-%m-%dT%H:%M:%S.000%z}", fmt::localtime(now)));
}

void DumpRegisters(PEXCEPTION_POINTERS e) {
    auto record = e->ContextRecord;
    pCombinedLogger->info("Registers: ");
    pCombinedLogger->info("  RAX: 0x{:016X}  RBX: 0x{:016X}  RCX: 0x{:016X}", record->Rax, record->Rbx, record->Rcx);
    pCombinedLogger->info("  RDX: 0x{:016X}  RSI: 0x{:016X}  RDI: 0x{:016X}", record->Rdx, record->Rsi, record->Rdi);
    pCombinedLogger->info("  RBP: 0x{:016X}  RSP: 0x{:016X}  R8:  0x{:016X}", record->Rbp, record->Rsp, record->R8);
    pCombinedLogger->info("  R9:  0x{:016X}  R10: 0x{:016X}  R11: 0x{:016X}", record->R9, record->R10, record->R11);
    pCombinedLogger->info("  R12: 0x{:016X}  R13: 0x{:016X}  R14: 0x{:016X}", record->R12, record->R13, record->R14);
    pCombinedLogger->info("  R15: 0x{:016X}", record->R15);
    pCombinedLogger->info("  RIP: 0x{:016X}  EFLAGS: 0x{:08X}", record->Rip, record->EFlags);
    pCombinedLogger->info("  DR0: 0x{:016X}  DR1: 0x{:016X}  DR2: 0x{:016X}", record->Dr0, record->Dr1, record->Dr2);
    pCombinedLogger->info("  DR3: 0x{:016X}  DR6: 0x{:016X}  DR7: 0x{:016X}", record->Dr3, record->Dr6, record->Dr7);
    pCombinedLogger->info(
        "  CS: 0x{:04X}  DS: 0x{:04X}   ES: 0x{:04X}  FS: 0x{:04X}   GS: 0x{:04X}  SS: 0x{:04X}",
        record->SegCs,
        record->SegDs,
        record->SegEs,
        record->SegFs,
        record->SegGs,
        record->SegSs
    );
}

void DumpLastAssembly(PEXCEPTION_POINTERS e) {
    pCombinedLogger->info("Last Assembly: ");
    constexpr auto MAX_INSTRUCTION_LEN = 64;
    char           instructions[MAX_INSTRUCTION_LEN];
    auto           startAddress = e->ContextRecord->Rip;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(startAddress), instructions, MAX_INSTRUCTION_LEN, nullptr)) {
        pCombinedLogger->error("  Failed to read memory from process! Error Code: 0x{:X}", GetLastError());
        return;
    }
    ZydisDecoder            decoder;
    ZydisFormatter          formatter;
    ZydisDecodedInstruction instruction;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64))) {
        pCombinedLogger->info("  Failed to initialize decoder!");
        return;
    }
    if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL))) {
        pCombinedLogger->info("  Failed to initialize formatter!");
        return;
    }
    if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, instructions, MAX_INSTRUCTION_LEN, &instruction))) {
        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer), startAddress);
        pCombinedLogger->info("  0x{:012X} --> {}", startAddress, buffer);
    } else {
        pCombinedLogger->info("  Failed to disassemble!");
    }
}

void DumpExceptionInfo(PEXCEPTION_POINTERS e) {
    using StringUtils::w2u8;

    auto record = e->ExceptionRecord;
    auto moduleName =
        w2u8(SymbolHelper::MapModuleFromAddr(hProcess, reinterpret_cast<DWORD64>(record->ExceptionAddress)));
    pCombinedLogger->info("Exception Info: ");
    if (record->ExceptionCode == CRT_EXCEPTION_CODE) {
        pCombinedLogger->info("  C++ STL Exception detected");
    }
    pCombinedLogger->info("  Code: 0x{:X}", record->ExceptionCode);
    pCombinedLogger->info("  Module: {}", moduleName);
    pCombinedLogger->info("  Address: 0x{:012X}", (int64_t)record->ExceptionAddress);
    pCombinedLogger->info("  Flags: 0x{:X}", record->ExceptionFlags);
    pCombinedLogger->info("  Number of Parameters: {}", record->NumberParameters);
    for (int i = 0; i < record->NumberParameters; i++) {
        pCombinedLogger->info("  Parameter {}: 0x{:X}", i, record->ExceptionInformation[i]);
    }
}

std::string MyUnDecorateSymbolName(const wchar_t* name) {
    std::wstring undecoratedName(0x1000, 0);

    auto decorateFlag = UNDNAME_NAME_ONLY | UNDNAME_NO_THISTYPE | UNDNAME_NO_ACCESS_SPECIFIERS |
                        UNDNAME_NO_ALLOCATION_MODEL | UNDNAME_NO_ALLOCATION_LANGUAGE | UNDNAME_NO_CV_THISTYPE |
                        UNDNAME_NO_FUNCTION_RETURNS | UNDNAME_NO_LEADING_UNDERSCORES | UNDNAME_NO_MEMBER_TYPE |
                        UNDNAME_NO_MS_KEYWORDS | UNDNAME_NO_RETURN_UDT_MODEL | UNDNAME_NO_THROW_SIGNATURES;
    if (auto size = UnDecorateSymbolNameW(name, undecoratedName.data(), undecoratedName.size(), decorateFlag)) {
        undecoratedName.resize(size);
        return StringUtils::w2u8(undecoratedName);
    }
    return StringUtils::w2u8(name);
}

void DumpStacktrace(PEXCEPTION_POINTERS e) {
    using std::string;
    using StringUtils::w2u8;

    pCombinedLogger->info("Stacktrace: ");
    STACKFRAME64 stackFrame     = {0};
    stackFrame.AddrPC.Mode      = AddrModeFlat;
    stackFrame.AddrPC.Offset    = e->ContextRecord->Rip;
    stackFrame.AddrStack.Mode   = AddrModeFlat;
    stackFrame.AddrStack.Offset = e->ContextRecord->Rsp;
    stackFrame.AddrFrame.Mode   = AddrModeFlat;
    stackFrame.AddrFrame.Offset = e->ContextRecord->Rbp;
    PCONTEXT pContext           = e->ContextRecord;
    int      counter            = -1;
    while (StackWalk64(
        MACHINE_TYPE,
        hProcess,
        hThread,
        &stackFrame,
        pContext,
        nullptr,
        SymFunctionTableAccess64,
        SymGetModuleBase64,
        nullptr
    )) {
        counter++;
        DWORD64 pc = stackFrame.AddrPC.Offset;
        DWORD64 displacement{};

        string                       moduleName = w2u8(SymbolHelper::MapModuleFromAddr(hProcess, pc));
        std::unique_ptr<SYMBOL_INFO> info(SymbolHelper::GetSymbolInfo(hProcess, pc, &displacement));
        if (!info) {
            pCombinedLogger->info("  #{} at pc 0x{:012X} {}", counter, pc, moduleName);
            continue;
        }
        string          symbolName       = MyUnDecorateSymbolName(info->Name);
        DWORD64         address          = info->Address;
        DWORD           lineDisplacement = 0;
        IMAGEHLP_LINE64 line{};
        line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
        if (!SymGetLineFromAddrW64(hProcess, pc, &lineDisplacement, &line)) {
            pCombinedLogger
                ->info("  #{} at pc 0x{:012X} {} -> {}+0x{:X}", counter, address, moduleName, symbolName, displacement);
            continue;
        }
        string sourceFile = StringUtils::w2u8(line.FileName);
        string sourceLine = std::to_string(line.LineNumber) + "L";
        std::replace(sourceFile.begin(), sourceFile.end(), '\\', '/');
        auto pos = sourceFile.find_last_of('/');
        if (pos != string::npos) {
            sourceFile = sourceFile.substr(pos + 1);
        }
        pCombinedLogger->info(
            "  #{} at pc 0x{:012X} {} -> {}+0x{:X} [{}:{}]",
            counter,
            address,
            moduleName,
            symbolName,
            displacement,
            sourceFile,
            sourceLine
        );
        suspectedModules.insert(moduleName);
    }
}

void DumpModules() {
    using StringUtils::w2u8;

    std::map<std::string, DWORD64> moduleMap;
    for (auto& [moduleBase, wModuleName] : SymbolHelper::moduleMap) {
        auto hModule       = reinterpret_cast<HMODULE>(moduleBase);
        auto moduleName    = w2u8(wModuleName);
        auto moduleVersion = w2u8(SymbolHelper::GetModuleVersionStr(hProcess, hModule));
        auto moduleStr     = moduleName;
        if (moduleVersion.empty() && (moduleName == "bedrock_server_mod.exe" || moduleName == "bedrock_server.exe"))
            moduleVersion = crashlogger::BdsVersion;
        if (!moduleVersion.empty())
            moduleStr += "<" + moduleVersion + ">";
        moduleMap[moduleStr] = moduleBase;
    }
    pCombinedLogger->info("Modules: ");
    for (auto& [moduleName, moduleBase] : moduleMap) {
        pCombinedLogger->info("  0x{:012X}  {}", moduleBase, moduleName);
    }
}

inline void
FindSymbols(std::unordered_set<std::wstring>& pdbDirs, const std::filesystem::path& dirPath, bool recursion = false) {
    using namespace std::filesystem;
    std::queue<directory_entry> dirList({directory_entry(dirPath)});
    std::error_code             ec;
    while (!dirList.empty()) {
        directory_entry entry = dirList.front();
        dirList.pop();
        auto dirIter = directory_iterator(entry, ec);
        if (ec) {
            ec.clear();
            continue;
        }
        for (auto& it : dirIter) {
            if (it.is_directory() && recursion) {
                dirList.push(it);
                continue;
            }
            if (it.path().extension() != ".pdb") {
                continue;
            }
            auto canonicalPath = canonical(it.path(), ec);
            if (ec) {
                ec.clear();
                continue;
            }
            auto dir = canonicalPath.remove_filename();
            pdbDirs.insert(dir.native());
        }
    }
}

bool LoadSymbolFiles() {
    try {
        auto homePathBuf = std::wstring(MAX_PATH, L'\0');
        auto homePathLen = GetEnvironmentVariableW(L"USERPROFILE", homePathBuf.data(), MAX_PATH);
        if (homePathLen == 0) {
            pLogger->error("Failed to get user home directory");
            return false;
        }
        homePathBuf.resize(homePathLen);
        std::filesystem::path            homeDir  = homePathBuf;
        std::filesystem::path            cacheDir = std::filesystem::absolute(homeDir) / ".symcache";
        std::unordered_set<std::wstring> pdbDirs;
        std::wstring                     symbolPath;

        FindSymbols(pdbDirs, targetDirPath, true);
        for (auto& dir : pdbDirs) {
            symbolPath += dir.substr(0, dir.size() - 1) + L";";
        }
        symbolPath += L"srv*" + cacheDir.native() + L"*https://msdl.microsoft.com/download/symbols";
        SymSetOptions(SymGetOptions() + SYMOPT_EXACT_SYMBOLS - SYMOPT_UNDNAME);
        pLogger->info("Loading symbol files from local and remote servers, this may take a while...");
        pLogger->info("Online symbol files will be cached in {}", StringUtils::w2u8(cacheDir.native()));
        if (!SymInitializeW(hProcess, symbolPath.c_str(), TRUE)) {
            pLogger->error("Failed to load symbol files! Error Code: {}", GetLastError());
            return false;
        }
        return true;
    } catch (std::exception& e) {
        pLogger->error("Failed to load symbol files! Error: {}", e.what());
        return false;
    }
}

void Break() { pCombinedLogger->info(""); }

void LogCrash(PEXCEPTION_POINTERS e, HANDLE _hProcess, HANDLE _hThread, DWORD _dProcessId, DWORD _dThreadId) {
    using std::chrono::system_clock;

    hProcess    = _hProcess;
    hThread     = _hThread;
    dwProcessId = _dProcessId;
    dwThreadId  = _dThreadId;
    date        = fmt::format("{:%Y-%m-%d_%H-%M-%S}", fmt::localtime(system_clock::now()));

    printf("\n");
    pLogger->set_level(spdlog::level::info);
    pLogger->info("BDS Crashed! Generating Stacktrace and MiniDump...");

    auto targetPathBuf = std::wstring(MAX_PATH, L'\0');
    if (auto targetPathLen = GetModuleFileNameExW(hProcess, nullptr, targetPathBuf.data(), MAX_PATH)) {
        targetPathBuf.resize(targetPathLen);
        targetExePath = targetPathBuf;
        targetDirPath = targetExePath.parent_path();
    } else {
        pLogger->error("Failed to get target path");
        return;
    }

    logDirPath = targetDirPath / CRASHLOGGER_LOG_DIR;
    if (!std::filesystem::is_directory(logDirPath) && !std::filesystem::create_directory(logDirPath)) {
        pLogger->error("Failed to create log directory");
        return;
    }

    if (!SymbolHelper::CreateModuleMap(hProcess)) {
        pLogger->error("Failed to create module map!");
        return;
    }

    GenerateMiniDumpFile(e);

    if (!LoadSymbolFiles()) {
        pLogger->error("Failed to load symbol files!");
        return;
    }

    pLogger->info("");

    if (!InitFileLogger()) {
        pLogger->error("Failed to initialize file logger!");
        pCombinedLogger = pLogger;
    }

    DumpSystemInfo();
    Break();
    DumpExceptionInfo(e);
    Break();
    DumpRegisters(e);
    Break();
    DumpLastAssembly(e);
    Break();
    DumpStacktrace(e);
    Break();
    DumpModules();
    pCombinedLogger->flush();

    if (!crashlogger::isEnableSentry) {
        pLogger->info("Sentry is disabled, skipping upload...");
        SymCleanup(hProcess);
        return;
    }

    SentryUploader sentryUploader{
        crashlogger::UserName,
        minidmpName,
        minidmpPath,
        traceName,
        tracePath,
        crashlogger::IsDev,
        crashlogger::LeviVersion
    };
    for (auto& [name, dsn, version] : ModHelper::pendingMods) {
        sentryUploader.addModSentryInfo(name, dsn, version);
    }
    sentryUploader.uploadAll();
    SymCleanup(hProcess);
}

} // namespace crashlogger::Logger
