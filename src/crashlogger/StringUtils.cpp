#include "crashlogger/StringUtils.h"

#include <Windows.h>
#include <string_view>

namespace crashlogger::StringUtils {

template <>
std::wstring Converter<Encoding::ANSI, Encoding::UTF16>::convert(std::string_view str) {
    auto acp = GetACP();
    int  len = MultiByteToWideChar(acp, 0, str.data(), (int)str.size(), nullptr, 0);
    if (len == 0) {
        return {};
    }
    std::wstring wstr(len, L'\0');
    MultiByteToWideChar(acp, 0, str.data(), (int)str.size(), wstr.data(), len);
    return wstr;
}

template <>
std::string Converter<Encoding::UTF16, Encoding::ANSI>::convert(std::wstring_view str) {
    auto acp = GetACP();
    int  len = WideCharToMultiByte(acp, 0, str.data(), (int)str.size(), nullptr, 0, nullptr, nullptr);
    if (len == 0) {
        return {};
    }
    std::string ret(len, '\0');
    WideCharToMultiByte(acp, 0, str.data(), (int)str.size(), ret.data(), (int)ret.size(), nullptr, nullptr);
    return ret;
}

template <>
std::wstring Converter<Encoding::UTF8, Encoding::UTF16>::convert(std::string_view str) {
    int len = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0);
    if (len == 0) {
        return {};
    }
    std::wstring wstr(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), wstr.data(), len);
    return wstr;
}

template <>
std::string Converter<Encoding::UTF16, Encoding::UTF8>::convert(std::wstring_view str) {
    int len = WideCharToMultiByte(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0, nullptr, nullptr);
    if (len == 0) {
        return {};
    }
    std::string ret(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, str.data(), (int)str.size(), ret.data(), (int)ret.size(), nullptr, nullptr);
    return ret;
}

template <>
std::string Converter<Encoding::UTF8, Encoding::ANSI>::convert(std::string_view str) {
    std::wstring wstr = Converter<Encoding::UTF8, Encoding::UTF16>::convert(str);
    return Converter<Encoding::UTF16, Encoding::ANSI>::convert(wstr);
}

template <>
std::string Converter<Encoding::ANSI, Encoding::UTF8>::convert(std::string_view str) {
    std::wstring wstr = Converter<Encoding::ANSI, Encoding::UTF16>::convert(str);
    return Converter<Encoding::UTF16, Encoding::UTF8>::convert(wstr);
}

} // namespace crashlogger::StringUtils
