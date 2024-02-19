# CrashLogger

Show crash log of LeviLamina

This utility helps generate crash reports and dump files when LeviLamina crashes. The crash report includes system information, exception information, registers information, current instruction, call stack, and modules and addresses.

## Install

```sh
lip install github.com/LiteLDev/CrashLogger
```

## Usage

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

- Put `dbghelp.dll` and `symsrv.dll` in the same directory as CrashLogger.exe, or **online symbol server will not work**.
- Logs will be saved in `./logs/crash` directory of bedrock server executable's directory.
- Specify the version of BDS gets a better crash report.
- Online symbol cache directory is `%USERPROFILE%/.symcache`, you can delete it to clear the cache.
- Currently, usage like `CrashLogger pid version[optional]` is supported for compatibility with LiteLoaderBDS. It is not recommended to use it. Please use `CrashLogger -p pid -b version` instead. The old usage will be removed in the future.

## Contributing

Ask questions by creating an issue.

PRs accepted.

## License

GPL-3.0-or-later © LiteLDev
