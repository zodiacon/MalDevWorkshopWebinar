// EncDecSection.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>

int Error(const char* text, DWORD err = GetLastError()) {
	printf("%s (%u)\n", text, err);
	return 1;
}

void EncDecSection(PVOID base, IMAGE_SECTION_HEADER* section) {
	auto data = section->PointerToRawData + (PBYTE)base;
	auto size = section->SizeOfRawData;

	BYTE xorCode[] = { 0x45, 0x12, 0x87, 0xff, 0x47, 0x88, 0xc5 };
	for (DWORD i = 0; i < size; i++) {
		data[i] ^= xorCode[i % sizeof(xorCode)];
	}
}

int main(int argc, const char* argv[]) {
	if (argc < 3) {
		printf("Usage: EncDecSection <image_path> <section_name>\n");
		return 0;
	}

	auto hFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return Error("Error opening file");

	auto hMemMap = CreateFileMapping(hFile, nullptr, PAGE_READWRITE, 0, 0, nullptr);
	if (!hMemMap)
		return Error("Failed to create MMF");
	CloseHandle(hFile);

	auto p = (IMAGE_DOS_HEADER*)MapViewOfFile(hMemMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (!p)
		return Error("Failed to map file");

	auto ntHeader = (IMAGE_NT_HEADERS64*)((PBYTE)p + p->e_lfanew);
	auto sections = (IMAGE_SECTION_HEADER*)(ntHeader + 1);
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		if (strcmp((const char*)sections->Name, argv[2]) == 0) {
			// found section
			EncDecSection(p, sections);
			UnmapViewOfFile(p);
			CloseHandle(hMemMap);
			return 0;
		}
		sections++;
	}
	printf("Section not found\n");
	return 1;
}

