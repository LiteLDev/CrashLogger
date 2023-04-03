add_rules("mode.debug", "mode.release")

set_policy("package.requires_lock", true)

set_runtimes("MD")

add_requires("cxxopts")
add_requires("spdlog")
add_requires("fmt")
add_requires("zydis")

target("CrashLogger")
    set_kind("binary")
    set_languages("c++20")
    set_symbols("debug")
    add_includedirs("include")
    add_cxflags("/utf-8")
    add_defines("UNICODE", "DBGHELP_TRANSLATE_TCHAR", "WIN32_LEAN_AND_MEAN", "NOMINMAX")
    add_syslinks("dbghelp", "version", "user32")
    add_files("src/**.cpp")
    add_packages("cxxopts","spdlog","fmt", "zydis")
