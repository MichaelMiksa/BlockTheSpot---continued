#include "pch.h"
#include "IAT_hook.h"
#include "WinTrust_hook.h"
#include "cef_url_hook.h"
#include "cef_zip_reader_hook.h"
#include "log_thread.h"
#include <delayimp.h> // Delay Load

static FARPROC WINAPI GetProcAddress_hook(HMODULE hModule, LPCSTR lpProcName)
{
	if (!lpProcName || 0 == HIWORD(lpProcName))
		return GetProcAddress_orig(hModule, lpProcName);

	if (0 == lstrcmpiA(lpProcName, "WinVerifyTrust")) {
		if (hModule == GetModuleHandleW(L"WinTrust.dll")) {
			return reinterpret_cast<FARPROC>(WinVerifyTrust_hook);
		}
	}

	return GetProcAddress_orig(hModule, lpProcName);
}

// https://www.ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking
bool process_IAT_hook_GetProcAddress(HMODULE module) noexcept
{
	if (!module) return false;

	if (nullptr == ImageDirectoryEntryToDataEx) {
		OutputDebugStringW(L"process_IAT_hook_GetProcAddress: ImageDirectoryEntryToDataEx is null.");
		return false;
	}

	ULONG size = 0;
	PIMAGE_IMPORT_DESCRIPTOR imports =
		reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(ImageDirectoryEntryToDataEx(
			module,
			TRUE, // image is loaded in memory
			IMAGE_DIRECTORY_ENTRY_IMPORT,
			&size,
			NULL
		));

	if (nullptr == imports) {
		return false;
	}

	for (; imports->Name; ++imports) {
		LPCSTR dll_name = reinterpret_cast<LPCSTR>(
			reinterpret_cast<BYTE*>(module) + imports->Name
			);

		// GetProcAddress is in kernel32
		if (0 == lstrcmpiA(dll_name, "kernel32.dll")) {

			PIMAGE_THUNK_DATA thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
				reinterpret_cast<BYTE*>(module) + imports->FirstThunk
				);

			for (; thunk->u1.Function; ++thunk) {
				PROC* func = reinterpret_cast<PROC*>(&thunk->u1.Function);

				if (*func == reinterpret_cast<PROC>(GetProcAddress)) {
					DWORD oldProtect;
					VirtualProtect(func, sizeof(PROC), PAGE_READWRITE, &oldProtect);

					GetProcAddress_orig = reinterpret_cast<GetProcAddress_t>(*func);
					*func = reinterpret_cast<PROC>(GetProcAddress_hook);

					VirtualProtect(func, sizeof(PROC), oldProtect, &oldProtect);
					return true;
				}
			}
		}
	}
	return false;
}
//
//bool IAT_unhook_GetProcAddress() noexcept
//{
//	HMODULE module = GetModuleHandleW(nullptr);
//	if (!module) return false;
//
//	PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
//	PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
//		reinterpret_cast<BYTE*>(module) + dos->e_lfanew
//		);
//
//	IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
//	if (!dir.VirtualAddress) return false;
//
//	PIMAGE_IMPORT_DESCRIPTOR imports = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
//		reinterpret_cast<BYTE*>(module) + dir.VirtualAddress
//		);
//
//	for (; imports->Name; ++imports) {
//		LPCSTR dll_name = reinterpret_cast<LPCSTR>(
//			reinterpret_cast<BYTE*>(module) + imports->Name
//			);
//
//		// GetProcAddress is in kernel32
//		if (0 == lstrcmpiA(dll_name, "kernel32.dll")) {
//
//			PIMAGE_THUNK_DATA thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
//				reinterpret_cast<BYTE*>(module) + imports->FirstThunk
//				);
//
//			for (; thunk->u1.Function; ++thunk) {
//				PROC* func = reinterpret_cast<PROC*>(&thunk->u1.Function);
//
//				if (*func == reinterpret_cast<PROC>(GetProcAddress_hook)) {
//					DWORD oldProtect;
//					VirtualProtect(func, sizeof(PROC), PAGE_READWRITE, &oldProtect);
//					*func = reinterpret_cast<PROC>(GetProcAddress_orig);
//					VirtualProtect(func, sizeof(PROC), oldProtect, &oldProtect);
//				}
//			}
//		}
//	}
//	return true;
//}



bool hook_libcef_IAT(HMODULE module, HMODULE libcef_dll_handle) noexcept
{
	if (!module || !libcef_dll_handle) {
		log_debug("hook_libcef_IAT: module or libcef handle is null.");
		return false;
	}

	if (nullptr == ImageDirectoryEntryToDataEx) {
		log_debug("hook_libcef_IAT: ImageDirectoryEntryToDataEx is null.");
		return false;
	}

	log_debug("hook_libcef_IAT: --- STARTING DELAY-LOAD IMPORTS SCAN (BY NAME) ---");

	ULONG size = 0;
	PIMAGE_DELAYLOAD_DESCRIPTOR delay_imports =
		reinterpret_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>(ImageDirectoryEntryToDataEx(
			module,
			TRUE,
			IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, // Directory Entry 13
			&size,
			NULL
		));

	if (delay_imports) {
		for (; delay_imports->DllNameRVA; ++delay_imports) {
			LPCSTR dll_name = reinterpret_cast<LPCSTR>(
				reinterpret_cast<BYTE*>(module) + delay_imports->DllNameRVA
				);

			if (0 == lstrcmpiA(dll_name, "libcef.dll")) {
				log_debug("hook_libcef_IAT: found libcef.dll in Delay-Load Imports!");

				// We get the tables of names (INT) and the one for adresses (IAT) in parallel
				PIMAGE_THUNK_DATA name_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
					reinterpret_cast<BYTE*>(module) + delay_imports->ImportNameTableRVA
					);
				PIMAGE_THUNK_DATA addr_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
					reinterpret_cast<BYTE*>(module) + delay_imports->ImportAddressTableRVA
					);

				bool patched = false;
				for (; name_thunk->u1.AddressOfData; ++name_thunk, ++addr_thunk) {
					// We check if the function is imported by name and not by ordinal number
					if (!IMAGE_SNAP_BY_ORDINAL(name_thunk->u1.Ordinal)) {
						PIMAGE_IMPORT_BY_NAME import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
							reinterpret_cast<BYTE*>(module) + name_thunk->u1.AddressOfData
							);
						LPCSTR func_name = reinterpret_cast<LPCSTR>(import_by_name->Name);

						// If the name matches, we re-write the IAT memory directly
						if (0 == lstrcmpiA(func_name, "cef_urlrequest_create")) {
							PROC* func = reinterpret_cast<PROC*>(&addr_thunk->u1.Function);
							DWORD oldProtect;
							VirtualProtect(func, sizeof(PROC), PAGE_READWRITE, &oldProtect);
							*func = reinterpret_cast<PROC>(cef_urlrequest_create_stub);
							VirtualProtect(func, sizeof(PROC), oldProtect, &oldProtect);
							log_debug("hook_libcef_IAT: patched delay-loaded cef_urlrequest_create by name successfully!");
							patched = true;
						}
						else if (0 == lstrcmpiA(func_name, "cef_zip_reader_create")) {
							PROC* func = reinterpret_cast<PROC*>(&addr_thunk->u1.Function);
							DWORD oldProtect;
							VirtualProtect(func, sizeof(PROC), PAGE_READWRITE, &oldProtect);
							*func = reinterpret_cast<PROC>(cef_zip_reader_create_stub);
							VirtualProtect(func, sizeof(PROC), oldProtect, &oldProtect);
							log_debug("hook_libcef_IAT: patched delay-loaded cef_zip_reader_create by name successfully!");
							patched = true;
						}
					}
				}
				if (patched) return true;
			}
		}
	}

	log_debug("hook_libcef_IAT: libcef.dll delay imports not found or patch not applied.");
	return false;
}
