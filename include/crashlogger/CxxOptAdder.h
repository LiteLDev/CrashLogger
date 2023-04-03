#pragma once

#include "cxxopts.hpp"

class CxxOptsAdder {
    cxxopts::OptionAdder adder;

public:
    inline explicit CxxOptsAdder(cxxopts::Options& options, const std::string& groupName = "")
    : adder(options.add_options(groupName)) {}

    inline CxxOptsAdder&
    add(const std::string&                           opts,
        const std::string&                           desc,
        const std::shared_ptr<const cxxopts::Value>& value    = ::cxxopts::value<bool>(),
        std::string                                  arg_help = "") {
        adder(opts, desc, value, std::move(arg_help));
        return *this;
    }
};
