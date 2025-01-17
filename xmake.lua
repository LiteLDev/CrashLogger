add_rules("mode.debug", "mode.release")

add_requires(
    "cxxopts v3.1.1",
    "fmt 9.1.0",
    "spdlog v1.11.0",
    "zydis v3.2.1",
    "nlohmann_json v3.11.3"
)

add_requires("cpr 1.10.5", {configs = {ssl = true}})
if not has_config("vs_runtime") then
    set_runtimes("MD")
end

target("CrashLogger")
    add_cxflags("/utf-8")
    add_defines(
        "DBGHELP_TRANSLATE_TCHAR",
        "NOMINMAX", -- To avoid conflicts with std::min and std::max.
        "UNICODE", -- To enable Unicode support in Windows API.
        "WIN32_LEAN_AND_MEAN"
    )
    add_files("src/**.cpp")
    add_includedirs("include")
    add_packages(
        "cxxopts",
        "fmt",
        "spdlog",
        "zydis",
        "cpr",
        "nlohmann_json"
    )
    add_syslinks(
        "dbghelp",
        "user32",
        "version"
    )
    set_kind("binary")
    set_languages("cxx20")
