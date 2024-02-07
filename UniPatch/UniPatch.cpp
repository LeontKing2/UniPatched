#include <iostream>
#include <fstream>
#include <vector>
#include <Windows.h>
#include <Psapi.h>
#include "ArgShit.h"

constexpr auto SUSPENDED = 0x00000004;

struct Module {
    uint64_t patch_count = 0;
    std::vector<uint64_t> rva_offset;
    std::vector<uint64_t> file_offset;
    std::vector<uint64_t> org_byte;
    std::vector<uint64_t> rep_byte;
    std::string PE_Name;
};

struct PE_Stuff {
    std::vector<Module> mods;
    uint64_t total_patches = 0;
    int load_attempts = 2000;
    int patch_attempts = 200;
    DWORD load_wait = 1;
    DWORD patch_wait = 1;
    bool error = false;
};

// Convert RVA to Physical File Offset (PFO)
uint64_t rvaToPa(uint64_t offsetRVA, PIMAGE_NT_HEADERS peHeader, LPVOID lpFileBase) {
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(peHeader);
    uint64_t nSectionCount = peHeader->FileHeader.NumberOfSections;

    for (uint64_t i = 0; i < nSectionCount; ++i, ++sectionHeader) {
        if (sectionHeader->VirtualAddress <= offsetRVA &&
            offsetRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
            return (offsetRVA - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData);
        }
    }
    return 0;
}

// Read and parse .1337 file
void read1337(PE_Stuff& patch_info, const std::string& file_path) {
    std::ifstream inFile(file_path);
    if (!inFile.is_open()) {
        std::cerr << "Could not open file " << file_path << std::endl;
        patch_info.error = true;
        return;
    }

    Module module;
    std::string lineRead;
    while (std::getline(inFile, lineRead)) {
        if (lineRead[0] == '>') {
            module.PE_Name = lineRead.substr(1);
            patch_info.mods.push_back(module);
        }
        else {
            uint64_t rva, org_byte, rep_byte;
            sscanf_s(lineRead.c_str(), "%I64x-%I64x-%I64x", &rva, &org_byte, &rep_byte);

            patch_info.mods.back().rva_offset.push_back(rva);
            patch_info.mods.back().org_byte.push_back(org_byte);
            patch_info.mods.back().rep_byte.push_back(rep_byte);
            patch_info.total_patches++;
        }
    }
    inFile.close();
}

// Get the base address of the given module name in the process
uint64_t GetBaseAddress(PROCESS_INFORMATION process, WCHAR* name, int la, DWORD lw) {
    int attempts = 0;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    unsigned int i;

    while (attempts < la) {
        if (attempts % 100 == 0) std::cout << "Scanning for Modules...: " << std::dec << (int)(((float)attempts / (float)la) * 100) << "%" << std::endl;

        // Resume momentarily, get a list of all the modules in this process
        ResumeThread(process.hThread);
        if (!EnumProcessModulesEx(process.hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
            std::cerr << "EnumProcessModulesEx failed" << std::endl;
            return 0;
        }
        SuspendThread(process.hThread);

        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            WCHAR szModName[MAX_PATH];
            if (GetModuleFileNameExW(process.hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR))) {
                if (wcsstr(szModName, name)) {
                    std::cout << "MATCHED:" << szModName << std::endl << "BASE:0x" << std::hex << hMods[i] << std::endl;
                    return (uint64_t)hMods[i];
                }
            }
        }

        Sleep(lw);
        attempts++;
    }

    return 0;
}

// Patch the target file
void patchTargetFile(const Module& module, const ArgShit& argShit) {
    std::fstream target;
    char o_byte[1];

    for (uint64_t p = 0; p < module.patch_count; p++) {
        target.open(module.PE_Name, std::ios_base::binary | std::ios_base::out | std::ios_base::in);
        if (!target.is_open()) {
            std::cerr << "Unable to open target: " << module.PE_Name << std::endl;
            return;
        }

        target.seekg((std::streamoff)module.file_offset[p]);
        target.read(o_byte, 1);
        if (o_byte[0] != (char)module.org_byte[p] && !argShit.contains("-f")) {
            std::cerr << "Original byte mismatch at address: 0x" << std::hex << module.file_offset[p] << std::endl
                << "Expected: 0x" << std::hex << module.org_byte[p] << " Read: 0x" << std::hex << (int)o_byte[0] << std::endl;
            return;
        }

        target.seekp((std::streamoff)module.file_offset[p]);
        target.write((char*)&module.rep_byte[p], 1);

        target.close();
    }
}

// Main function
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: UniPatch.exe <1337_file_path>" << std::endl;
        return -1;
    }

    // Parse command-line arguments
    ArgShit argShit(argv, argc);

    // Create PE_Stuff object to store patch information
    PE_Stuff patch_info;

    // Read and parse the .1337 file
    read1337(patch_info, argShit.getArg(1));

    if (patch_info.error) {
        std::cerr << "Error reading .1337 file." << std::endl;
        return -1;
    }

    PROCESS_INFORMATION processInfo;
    STARTUPINFO startupInfo;

    // Set up the STARTUPINFO structure.
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);

    // Launch the target process in a suspended state
    if (!CreateProcess(L"target.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo)) {
        std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;
        return -1;
    }

    // Iterate over modules and apply patches
    for (auto& module : patch_info.mods) {
        module.patch_count = module.rva_offset.size();

        // Get the base address of the module in the target process
        uint64_t baseAddress = GetBaseAddress(processInfo, (WCHAR*)module.PE_Name.c_str(), patch_info.load_attempts, patch_info.load_wait);
        if (baseAddress == 0) {
            std::cerr << "Unable to find module: " << module.PE_Name << std::endl;
            return -1;
        }

        // Get the DOS header and PE header
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
        PIMAGE_NT_HEADERS peHeader = (PIMAGE_NT_HEADERS)(baseAddress + dosHeader->e_lfanew);

        // Convert RVA to physical file offset for each patch
        for (uint64_t p = 0; p < module.patch_count; ++p) {
            module.file_offset.push_back(rvaToPa(module.rva_offset[p], peHeader, (LPVOID)baseAddress));
        }

        // Patch the target file
        patchTargetFile(module, argShit);
    }

    // Resume the main thread of the target process
    ResumeThread(processInfo.hThread);

    // Wait for the target process to exit
    WaitForSingleObject(processInfo.hProcess, INFINITE);

    // Close process and thread handles
    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);

    return 0;
}
