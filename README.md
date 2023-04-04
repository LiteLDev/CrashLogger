# CrashLogger

_part of LiteLoaderBDS Toolchain_

## Features

### Generate a minidump file

### Generate a crash report with the following information

- System Information
- Exception Information
- Registers Information
- Current Instruction
- Call Stack
- Modules and addresses

## Usages

### Launch by LiteLoader

_CrashLogger will be launched automatically as LiteLoader is loaded._

### Use a Command Line

```text
Usage:
  CrashLogger [OPTION...]

  -h, --help     Print this help message
  -v, --version  Print version information
  -s, --silent   Silent mode, no console output except for crash report and error messages
  -b, --bds arg  The version of the BDS to be attached (default: 0.0.0.0)
  -p, --pid arg  The PID of the process to be attached (default: -1)
```

## Notes

1. Put `dbghelp.dll` and `symsrv.dll` in the same directory as CrashLogger.exe, or **online symbol server will not work**.
2. Logs will be saved in `./logs/crash` directory of bedrock server executable's directory.
3. Specify the version of BDS gets a better crash report.
4. Online symbol cache directory is `%USERPROFILE%/.symcache`, you can delete it to clear the cache.
5. Currently, usage like `CrashLogger pid version[optional]` is supported for compatibility with LiteLoaderBDS. It is not recommended to use it. Please use `CrashLogger -p pid -b version` instead. The old usage will be removed in the future.

## Preview

### Examples

[trace_2023-04-03_21-48-53.log](https://github.com/LiteLDev/CrashLogger/blob/main/examples/trace_2023-04-03_21-48-53.log)

### Picture

![pic](https://github.com/LiteLDev/CrashLogger/blob/main/examples/console.png?raw=true)
