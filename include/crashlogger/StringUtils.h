#pragma once

#include <string>
#include <string_view>

namespace crashlogger::StringUtils {

enum class Encoding { ANSI, UTF8, UTF16 };

template <Encoding From, Encoding To>
struct Converter {
    using ReturnType = std::conditional_t<To == Encoding::UTF16, std::wstring, std::string>;
    using ParamType  = std::conditional_t<From == Encoding::UTF16, std::wstring_view, std::string_view>;

    static ReturnType convert(ParamType str);

    ReturnType operator()(ParamType str) { return convert(str); }
};

[[maybe_unused]] inline auto w2u8 = Converter<Encoding::UTF16, Encoding::UTF8>{};
[[maybe_unused]] inline auto u82w = Converter<Encoding::UTF8, Encoding::UTF16>{};
[[maybe_unused]] inline auto a2u8 = Converter<Encoding::ANSI, Encoding::UTF8>{};
[[maybe_unused]] inline auto u82a = Converter<Encoding::UTF8, Encoding::ANSI>{};
[[maybe_unused]] inline auto a2w  = Converter<Encoding::ANSI, Encoding::UTF16>{};
[[maybe_unused]] inline auto w2a  = Converter<Encoding::UTF16, Encoding::ANSI>{};

constexpr std::string& replaceAll(std::string& str, std::string_view oldValue, std::string_view newValue) {
    for (std::string::size_type pos(0); pos != std::string::npos; pos += newValue.length()) {
        if ((pos = str.find(oldValue, pos)) != std::string::npos) str.replace(pos, oldValue.length(), newValue);
        else break;
    }
    return str;
}

} // namespace crashlogger::StringUtils
