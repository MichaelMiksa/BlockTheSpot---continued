#include "pch.h"

constexpr auto ORIGINAL_CHROME_ELF_DLL = L"./chrome_elf_required.dll";

extern "C"
LPVOID WINAPI LoadAPI(const char* api_name)
{
    static const std::wstring path{ ORIGINAL_CHROME_ELF_DLL };
    static std::unordered_map<std::string, FARPROC> function_map;

    static HMODULE hModule = GetModuleHandleW(path.c_str());
    if (!hModule) {
        hModule = LoadLibraryW(path.c_str());
        if (!hModule) {
            return nullptr;
        }
    }

    if (function_map.find(api_name) == function_map.end()) {
        FARPROC proc = GetProcAddress(hModule, api_name);
        if (!proc) {
            return nullptr;
        }
        function_map[api_name] = proc;
    }

    return reinterpret_cast<LPVOID>(function_map[api_name]);
}
