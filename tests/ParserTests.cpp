#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <Parser.hpp>

#include <tuple>
#include <winnt.h>
#include "better_braces.hpp"

namespace PE_PARSER{
    std::unique_ptr<IMAGE_IMPORT_BY_NAME> createImageImportByName(WORD hint, const char* name){
        size_t nameLength = std::strlen(name) + 1; // +1 for null terminator
        size_t totalSize = sizeof(IMAGE_IMPORT_BY_NAME) + nameLength - 1; // -1 because Name[1] already accounts for one char

        auto importByName = std::unique_ptr<IMAGE_IMPORT_BY_NAME>((IMAGE_IMPORT_BY_NAME*)malloc(totalSize));

        std::memcpy(importByName->Name, name, nameLength);
        importByName->Hint = hint;

        return importByName;
    }

    std::pair<std::optional<WORD>, std::unique_ptr<IMAGE_IMPORT_BY_NAME>> createNameTable(WORD hint, const char* name, std::optional<WORD> ordinal = std::nullopt){
        return std::make_pair(ordinal, createImageImportByName(hint, name));
    }

    MATCHER_P(MatchesImageSectionHeader, expected, "Check equality of image section header structs") {
        return std::equal(std::begin(arg.Name), std::end(arg.Name), std::begin(expected.Name)) &&
               arg.Misc.PhysicalAddress == expected.Misc.PhysicalAddress &&
               arg.VirtualAddress == expected.VirtualAddress &&
               arg.SizeOfRawData == expected.SizeOfRawData &&
               arg.PointerToRawData == expected.PointerToRawData &&
               arg.PointerToRelocations == expected.PointerToRelocations &&
               arg.PointerToLinenumbers == expected.PointerToLinenumbers &&
               arg.NumberOfRelocations == expected.NumberOfRelocations &&
               arg.NumberOfLinenumbers == expected.NumberOfLinenumbers &&
               arg.Characteristics == expected.Characteristics;
    }

    MATCHER_P(MatchesDataDirectory, expected, "Check equality of data directory structs") {
        return arg.OriginalFirstThunk == expected.OriginalFirstThunk &&
               arg.TimeDateStamp == expected.TimeDateStamp &&
               arg.ForwarderChain == expected.ForwarderChain &&
               arg.Name == expected.Name &&
               arg.FirstThunk == expected.FirstThunk;
    }

    TEST(ParserTest, Parse) {

        PE_PARSER::Parser parser;
        PE_DATA::PEFile *peFile = parser.loadPEFileFromPath("D:/PE-Parser/tests/Test_PEs/1.exe");

        EXPECT_ANY_THROW({
                             std::ignore = peFile->baseOfData();
                         });

        //DosHeader byte data
        ASSERT_THAT(
                (std::vector<uint64_t>{
                        peFile->magicNumber(), peFile->lastPageBytes(), peFile->pagesInFile(), peFile->relocations(),
                        peFile->sizeOfHeaderInParagraphs(), peFile->minimumExtraParagraphs(),
                        peFile->maximumExtraParagraphs(),
                        peFile->initialSSValue(), peFile->initialSPValue(), peFile->checkSum(),
                        peFile->initialIPValue(),
                        peFile->initialCSValue(), peFile->addressRelocationTable(), peFile->overlayNumber(),
                        peFile->oemIdentifier(), peFile->oemInformation(), peFile->headerAddress()
                }),
                ::testing::ElementsAreArray(
                        std::vector<uint64_t>{
                                0x5A4D, 0x0090, 0x0003, 0x0000, 0x0004, 0x00000, 0xFFFF, 0x0000, 0x00B8,
                                0x0000, 0x0000, 0x0000, 0x0040, 0x0000, 0x0000, 0x000, 0x00000128
                        }
                )
        );

        //ImageHeader byte data
        ASSERT_THAT(
                (std::vector<uint64_t>{
                        peFile->signature(), peFile->machine(), peFile->numberOfSections(),
                        peFile->timeDateStamp(), peFile->pointerToSymbolTable(), peFile->numberOfSymbols(),
                        peFile->sizeOfOptionalHeader(), peFile->charasteristics()
                }),
                ::testing::ElementsAreArray(
                        std::vector<uint64_t>{
                                0x00004550, 0x8664, 0x0006, 0x615074eb,
                                0x00000000, 0x00000000, 0x00F0, 0x0022
                        }
                )
        );

        //OptionalHeader byte data
        ASSERT_THAT(
                (std::vector<uint64_t>{
                        peFile->magic(), peFile->majorLinkerVersion(), peFile->minorLinkerVersion(),
                        peFile->sizeOfCode(), peFile->sizeOfInitializedData(), peFile->sizeOfUninitializedData(),
                        peFile->addressOfEntryPoint(), peFile->baseOfCode(), peFile->imageBase(),
                        peFile->sectionAlignment(), peFile->fileAlignment(), peFile->majorOperatingSystemVersion(),
                        peFile->minorOperatingSystemVersion(), peFile->majorImageVersion(), peFile->minorImageVersion(),
                        peFile->majorSubsystemVersion(), peFile->minorSubsystemVersion(), peFile->win32VersionValue(),
                        peFile->sizeOfImage(), peFile->sizeOfHeaders(), peFile->checkSumOptional(),
                        peFile->dllCharasteristics(), peFile->sizeOfStackReserve(),
                        peFile->sizeOfStackCommit(), peFile->sizeOfHeapReserve(), peFile->sizeOfHeapCommit(),
                        peFile->loaderFlags(), peFile->numberOfRvaAndSizes()
                }),
                ::testing::ElementsAreArray(
                        std::vector<uint64_t>{
                                0x020B, 0x0E, 0x10, 0x00333400, 0x0029FE00, 0x00000000,
                                0x002CD4B4, 0x00001000, 0x0000000140000000, 0x00001000,
                                0x00000200, 0x0005, 0x0002, 0x0001, 0x0000, 0x0005,
                                0x0002, 0x00000000, 0x005D8000, 0x00000400, 0x005C561D,
                                0x00008160, 0x0000000000100000, 0x0000000000001000,
                                0x0000000000100000, 0x0000000000001000, 0x00000000, 0x00000010
                        }
                )
        );

        //DataDirectory byte data
        ASSERT_THAT(
                (std::vector<std::pair<DWORD, std::size_t>>{
                        peFile->exportDirectory(), peFile->importDirectory(), peFile->resourceDirectory(),
                        peFile->exceptionDirectory(),
                        peFile->securityDirectory(), peFile->baseRelocationDirectory(), peFile->debugDirectory(),
                        peFile->architectureDirectory(),
                        peFile->globalPtrDirectory(), peFile->tlsDirectory(), peFile->loadConfigDirectory(),
                        peFile->boundImportDirectory(),
                        peFile->iatDirectory(), peFile->delayImportDescriptor(), peFile->clrRuntimeHeader()
                }),
                ::testing::ElementsAreArray(
                        std::vector<std::pair<DWORD, std::size_t>>{
                                {0,        0},
                                {0x428A4C, 0x190},
                                {0X46E000, 0x163BA0},
                                {0x453000, 0x1A418},
                                {0x5BFC00, 0x19A8},
                                {0x5D2000, 0X51CC},
                                {0x3C2070, 0x54},
                                {0,        0},
                                {0,        0},
                                {0X3C21D0, 0x28},
                                {0x3C20D0, 0x100},
                                {0,        0},
                                {0x335000, 0x1248},
                                {0,        0},
                                {0,        0}
                        }
                )
        );

        //SectionHeaders byte data
        std::vector<IMAGE_SECTION_HEADER> sectionHeaders = *peFile->getSectionHeaders(),
                expectedHeaders{
                IMAGE_SECTION_HEADER{".text", 0x33324c, 0x1000, 0x333400, 0x400, 0x0, 0x0, 0x0, 0x0, 0x60000020},
                IMAGE_SECTION_HEADER{".rdata", 0xf765c, 0x335000, 0xF7800, 0x333800, 0x0, 0x0, 0x0, 0x0, 0x40000040},
                IMAGE_SECTION_HEADER{".data", 0x250ac, 0x42D000, 0x11800, 0x42B000, 0x0, 0x0, 0x0, 0x0, 0xC0000040},
                IMAGE_SECTION_HEADER{".pdata", 0x1a418, 0x453000, 0x1A600, 0x43C800, 0x0, 0x0, 0x0, 0x0, 0x40000040},
                IMAGE_SECTION_HEADER{".rsrc", 0x163ba0, 0x46E000, 0x163C00, 0x456E00, 0x0, 0x0, 0x0, 0x0, 0x40000040},
                IMAGE_SECTION_HEADER{".reloc", 0x51cc, 0x5D2000, 0x5200, 0x5BAA00, 0x0, 0x0, 0x0, 0x0, 0x42000040}
        };

        for (std::size_t i = 0; i < sectionHeaders.size(); i++) {
            EXPECT_THAT(sectionHeaders[i], MatchesImageSectionHeader(expectedHeaders[i]));
        }

        std::vector<IMAGE_IMPORT_DESCRIPTOR> importDirectory = (*peFile->getImportDirectoryTable()),
                expectedImportDirectory = std::vector<IMAGE_IMPORT_DESCRIPTOR>{
                {0x428C50, 0, 0, 0x429F7A, 0x335070},
                {0x4295B8, 0, 0, 0x42A0CE, 0x3359D8},
                {0x429568, 0, 0, 0x42A176, 0x335988},
                {0x429DB8, 0, 0, 0x42A192, 0x3361D8},
                {0x429D78, 0, 0, 0x42A1E0, 0x336198},
                {0x428D08, 0, 0, 0x42A2A0, 0x335128},
                {0x429DA8, 0, 0, 0x42A2BE, 0x3361C8},
                {0x429648, 0, 0, 0x42A2F8, 0x335A68},
                {0x429D98, 0, 0, 0x42A318, 0x3361B8},
                {0x428F48, 0, 0, 0x42A3EA, 0x335368},
                {0x429540, 0, 0, 0x42A402, 0x335960},
                {0x428F98, 0, 0, 0x42AA12, 0x3353B8},
                {0x429660, 0, 0, 0x42B7F4, 0x335A80},
                {0x428D50, 0, 0, 0x42BBC4, 0x335170},
                {0x428CF0, 0, 0, 0x42BBEA, 0x335110},
                {0x428BE0, 0, 0, 0x42BCE2, 0x335000},
                {0x429DC8, 0, 0, 0x42BDB2, 0x3361E8},
                {0x429550, 0, 0, 0x42BDBC, 0x335970},
                {0x429CF8, 0, 0, 0x42BF34, 0x336118}
        };

        for (int i = 0; i < expectedImportDirectory.size(); i++) {
            EXPECT_THAT(importDirectory[i], MatchesDataDirectory(expectedImportDirectory[i]));
        }

        //ImportDirectoryNames byte data
        ASSERT_THAT(
                *peFile->getImportDirectoryNames(),
                ::testing::ElementsAreArray(
                        std::vector<std::string>{
                                "COMCTL32.dll", "SHLWAPI.dll", "SHELL32.dll", "dbghelp.dll",
                                "VERSION.dll", "CRYPT32.dll", "WINTRUST.dll", "SensApi.dll",
                                "WININET.dll", "IMM32.dll", "MSIMG32.dll", "KERNEL32.dll",
                                "USER32.dll", "GDI32.dll", "COMDLG32.dll", "ADVAPI32.dll",
                                "ole32.dll", "OLEAUT32.dll", "UxTheme.dll"
                        }
                )
        );

        std::vector<std::vector<std::pair<std::optional<WORD>, std::unique_ptr<IMAGE_IMPORT_BY_NAME>>>>
                importByNameTable = std::move(*peFile->getImportByNameTable()), expectedImportByNameTable{};

        expectedImportByNameTable.push_back(init{
                createNameTable(0x51, "ImageList_BeginDrag"),
                createNameTable(0x5F, "ImageList_EndDrag"),
                createNameTable(0x76, "ImageList_SetIconSize"),
                createNameTable(0x59, "ImageList_DragMove"),
                createNameTable(0x5A, "ImageList_DragShowNolock"),
                std::make_pair(0x11, std::move(std::unique_ptr<IMAGE_IMPORT_BY_NAME>{})),
                createNameTable(0x50, "ImageList_AddMasked"),
                createNameTable(0x65, "ImageList_GetImageCount"),
                createNameTable(0x7C, "InitCommonControlsEx"),
                createNameTable(0x70, "ImageList_ReplaceIcon"),
                createNameTable(0x55, "ImageList_Destroy"),
                createNameTable(0x54, "ImageList_Create"),
                createNameTable(0x93, "_TrackMouseEvent"),
                createNameTable(0x66, "ImageList_GetImageInfo"),
                createNameTable(0x5B, "ImageList_Draw"),
                std::make_pair(0x19D, std::move(std::unique_ptr<IMAGE_IMPORT_BY_NAME>{})),
                std::make_pair(0x19C, std::move(std::unique_ptr<IMAGE_IMPORT_BY_NAME>{})),
                createNameTable(0x57, "ImageList_DragEnter"),
                std::make_pair(0x19A, std::move(std::unique_ptr<IMAGE_IMPORT_BY_NAME>{}))
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0x69, "PathIsRelativeW"),
                createNameTable(0xD, "ColorRGBToHLS"),
                createNameTable(0x99, "PathStripPathW"),
                createNameTable(0x37, "PathAppendW"),
                createNameTable(0x35, "PathAddExtensionW"),
                createNameTable(0x8D, "PathRemoveExtensionW"),
                createNameTable(0x5F, "PathIsDirectoryW"),
                createNameTable(0x3D, "PathCombineW"),
                createNameTable(0x8, "AssocQueryStringW"),
                createNameTable(0x7F, "PathMatchSpecW"),
                createNameTable(0x4D, "PathFindFileNameW"),
                createNameTable(0x59, "PathGetDriveNumberW"),
                createNameTable(0x42, "PathCompactPathExW"),
                createNameTable(0x4B, "PathFindExtensionW"),
                createNameTable(0x49, "PathFileExistsW"),
                createNameTable(0x8F, "PathRemoveFileSpecW"),
                createNameTable(0xC, "ColorHLSToRGB")
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0x140, "SHFileOperationW"),
                createNameTable(0x9F, "SHCreateItemFromParsingName"),
                createNameTable(0x29, "DragQueryPoint"),
                createNameTable(0x24, "DragFinish"),
                createNameTable(0x1B6, "ShellExecuteW"),
                std::make_pair(0xA5, std::move(std::unique_ptr<IMAGE_IMPORT_BY_NAME>{})),
                createNameTable(0x157, "SHGetFolderPathW"),
                createNameTable(0x28, "DragQueryFileW"),
                createNameTable(0x1C2, "Shell_NotifyIconW")
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0x16, "ImageNtHeader")
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0x7, "GetFileVersionInfoSizeW"),
                createNameTable(0x8, "GetFileVersionInfoW"),
                createNameTable(0x10, "VerQueryValueW")
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0xC5, "CryptQueryObject"),
                createNameTable(0x4B, "CertGetNameStringW"),
                createNameTable(0x56, "CertNameToStrW"),
                createNameTable(0x46, "CertGetCertificateContextProperty"),
                createNameTable(0x35, "CertFindCertificateInStore"),
                createNameTable(0x12, "CertCloseStore"),
                createNameTable(0xB5, "CryptMsgGetParam"),
                createNameTable(0xAE, "CryptMsgClose")
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0x8A, "WinVerifyTrust")
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0x1, "IsDestinationReachableW"),
                createNameTable(0x2, "IsNetworkAlive")
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0x9F, "InternetCrackUrlW")
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0x76, "ImmSetCompositionStringW"),
                createNameTable(0x2D, "ImmEscapeW"),
                createNameTable(0x39, "ImmGetCompositionStringW"),
                createNameTable(0x77, "ImmSetCompositionWindow"),
                createNameTable(0x74, "ImmSetCompositionFontW"),
                createNameTable(0x6B, "ImmReleaseContext"),
                createNameTable(0x3B, "ImmGetContext"),
                createNameTable(0x64, "ImmNotifyIME"),
                createNameTable(0x72, "ImmSetCandidateWindow")
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0x0, "AlphaBlend")
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0x341, "GlobalLock"),
                createNameTable(0x217, "GetCurrentDirectoryW"),
                createNameTable(0x336, "GlobalAlloc"),
                createNameTable(0x1AD, "FormatMessageW"),
                createNameTable(0x312, "GetTimeFormatEx"),
                createNameTable(0x227, "GetDateFormatEx"),
                createNameTable(0x3B4, "LCMapStringW"),
                createNameTable(0x168, "ExpandEnvironmentStringsW"),
                createNameTable(0x517, "SetCurrentDirectoryW"),
                createNameTable(0x1B1, "FreeLibrary"),
                createNameTable(0x3CA, "LoadResource"),
                createNameTable(0x3DE, "LockResource"),
                createNameTable(0x58A, "SizeofResource"),
                createNameTable(0x19C, "FindResourceW"),
                createNameTable(0x222, "GetCurrentThreadId"),
                createNameTable(0x86, "CloseHandle"),
                createNameTable(0x524, "SetEvent"),
                createNameTable(0x4CA, "ResetEvent"),
                createNameTable(0x5E6, "WaitForSingleObject"),
                createNameTable(0xBF, "CreateEventW"),
                createNameTable(0xF2, "CreateThread"),
                createNameTable(0xAD, "CopyFileW"),
                createNameTable(0xCB, "CreateFileW"),
                createNameTable(0x21D, "GetCurrentProcess"),
                createNameTable(0x21E, "GetCurrentProcessId"),
                createNameTable(0x3C7, "LoadLibraryW"),
                createNameTable(0x4B4, "ReleaseMutex"),
                createNameTable(0xDA, "CreateMutexW"),
                createNameTable(0x58B, "Sleep"),
                createNameTable(0x345, "GlobalSize"),
                createNameTable(0x64C, "lstrcpynW"),
                createNameTable(0x268, "GetLocalTime"),
                createNameTable(0x5E4, "WaitForMultipleObjects"),
                createNameTable(0xAA, "CopyFileExW"),
                createNameTable(0x116, "DeleteFileW"),
                createNameTable(0x324, "GetVersionExW"),
                createNameTable(0xC8, "CreateFileMappingW"),
                createNameTable(0x3E1, "MapViewOfFile"),
                createNameTable(0x5BF, "UnmapViewOfFile"),
                createNameTable(0x2FD, "GetTempPathW"),
                createNameTable(0x53F, "SetLastError"),
                createNameTable(0x71, "CancelIo"),
                createNameTable(0x58E, "SleepEx"),
                createNameTable(0x5E7, "WaitForSingleObjectEx"),
                createNameTable(0x45A, "QueueUserAPC"),
                createNameTable(0x476, "ReadDirectoryChangesW"),
                createNameTable(0x269, "GetLocaleInfoA"),
                createNameTable(0x30E, "GetTickCount"),
                createNameTable(0x3C4, "LoadLibraryA"),
                createNameTable(0x2DD, "GetStringTypeExW"),
                createNameTable(0x3B2, "LCMapStringA"),
                createNameTable(0x2DC, "GetStringTypeExA"),
                createNameTable(0x31B, "GetUserDefaultLCID"),
                createNameTable(0x12F, "DuplicateHandle"),
                createNameTable(0x5D8, "VirtualFree"),
                createNameTable(0x5D5, "VirtualAlloc"),
                createNameTable(0x27B, "GetModuleHandleA"),
                createNameTable(0x1B2, "FreeLibraryAndExitThread"),
                createNameTable(0x30C, "GetThreadTimes"),
                createNameTable(0x221, "GetCurrentThread"),
                createNameTable(0x5C5, "UnregisterWait"),
                createNameTable(0x4AD, "RegisterWaitForSingleObject"),
                createNameTable(0x313, "GetTimeFormatW"),
                createNameTable(0x2B6, "GetProcessAffinityMask"),
                createNameTable(0x290, "GetNumaHighestNodeNumber"),
                createNameTable(0x11B, "DeleteTimerQueueTimer"),
                createNameTable(0x78, "ChangeTimerQueueTimer"),
                createNameTable(0xFA, "CreateTimerQueueTimer"),
                createNameTable(0x26F, "GetLogicalProcessorInformation"),
                createNameTable(0x308, "GetThreadPriority"),
                createNameTable(0x56B, "SetThreadPriority"),
                createNameTable(0x589, "SignalObjectAndWait"),
                createNameTable(0x36C, "InitializeSListHead"),
                createNameTable(0x2D7, "GetStartupInfoW"),
                createNameTable(0x382, "IsDebuggerPresent"),
                createNameTable(0x389, "IsProcessorFeaturePresent"),
                createNameTable(0x59A, "TerminateProcess"),
                createNameTable(0x57B, "SetUnhandledExceptionFilter"),
                createNameTable(0x5BC, "UnhandledExceptionFilter"),
                createNameTable(0x4E1, "RtlVirtualUnwind"),
                createNameTable(0x4DA, "RtlLookupFunctionEntry"),
                createNameTable(0x4D3, "RtlCaptureContext"),
                createNameTable(0x26B, "GetLocaleInfoW"),
                createNameTable(0x9B, "CompareStringW"),
                createNameTable(0x1C7, "GetCPInfo"),
                createNameTable(0x2F0, "GetSystemTimeAsFileTime"),
                createNameTable(0x5AD, "TlsFree"),
                createNameTable(0x5AF, "TlsSetValue"),
                createNameTable(0x5AE, "TlsGetValue"),
                createNameTable(0x5AC, "TlsAlloc"),
                createNameTable(0x595, "SwitchToThread"),
                createNameTable(0x368, "InitializeCriticalSectionAndSpinCount"),
                createNameTable(0x451, "QueryPerformanceFrequency"),
                createNameTable(0x450, "QueryPerformanceCounter"),
                createNameTable(0x466, "RaiseException"),
                createNameTable(0x10A, "DecodePointer"),
                createNameTable(0x131, "EncodePointer"),
                createNameTable(0x4DC, "RtlPcToFileHeader"),
                createNameTable(0x2DE, "GetStringTypeW"),
                createNameTable(0x111, "DeleteCriticalSection"),
                createNameTable(0x5B5, "TryEnterCriticalSection"),
                createNameTable(0x3C0, "LeaveCriticalSection"),
                createNameTable(0x135, "EnterCriticalSection"),
                createNameTable(0xBA, "CreateDirectoryW"),
                createNameTable(0x97, "CompareFileTime"),
                createNameTable(0x64F, "lstrlenW"),
                createNameTable(0x643, "lstrcmpW"),
                createNameTable(0x24C, "GetFileAttributesW"),
                createNameTable(0x192, "FindNextFileW"),
                createNameTable(0x186, "FindFirstFileW"),
                createNameTable(0x17B, "FindClose"),
                createNameTable(0x60D, "WideCharToMultiByte"),
                createNameTable(0x3F2, "MultiByteToWideChar"),
                createNameTable(0x1B8, "GetACP"),
                createNameTable(0x33D, "GlobalFree"),
                createNameTable(0x27A, "GetModuleFileNameW"),
                createNameTable(0x322, "GetVersion"),
                createNameTable(0x3F1, "MulDiv"),
                createNameTable(0x3D2, "LocalFree"),
                createNameTable(0x3CD, "LocalAlloc"),
                createNameTable(0x228, "GetDateFormatW"),
                createNameTable(0x267, "GetLastError"),
                createNameTable(0x41C, "OutputDebugStringW"),
                createNameTable(0x646, "lstrcmpiW"),
                createNameTable(0x3C6, "LoadLibraryExW"),
                createNameTable(0x2B5, "GetProcAddress"),
                createNameTable(0x27E, "GetModuleHandleW"),
                createNameTable(0x5DB, "VirtualProtect"),
                createNameTable(0x4B8, "ReleaseSemaphore"),
                createNameTable(0x371, "InterlockedPopEntrySList"),
                createNameTable(0x348, "GlobalUnlock"),
                createNameTable(0x170, "FileTimeToSystemTime"),
                createNameTable(0x597, "SystemTimeToTzSpecificLocalTime"),
                createNameTable(0x3EB, "MoveFileExW"),
                createNameTable(0x649, "lstrcpyW"),
                createNameTable(0x52B, "SetFileAttributesW"),
                createNameTable(0x274, "GetLongPathNameW"),
                createNameTable(0x260, "GetFullPathNameW"),
                createNameTable(0x560, "SetThreadAffinityMask"),
                createNameTable(0x249, "GetFileAttributesExW"),
                createNameTable(0x372, "InterlockedPushEntrySList"),
                createNameTable(0x370, "InterlockedFlushSList"),
                createNameTable(0x446, "QueryDepthSList"),
                createNameTable(0x5C6, "UnregisterWaitEx"),
                createNameTable(0xF9, "CreateTimerQueue"),
                createNameTable(0x4E0, "RtlUnwindEx"),
                createNameTable(0x477, "ReadFile"),
                createNameTable(0x164, "ExitProcess"),
                createNameTable(0x27D, "GetModuleHandleExW"),
                createNameTable(0x165, "ExitThread"),
                createNameTable(0x2D9, "GetStdHandle"),
                createNameTable(0x621, "WriteFile"),
                createNameTable(0x34E, "HeapAlloc"),
                createNameTable(0x352, "HeapFree"),
                createNameTable(0x255, "GetFileType"),
                createNameTable(0x202, "GetConsoleMode"),
                createNameTable(0x474, "ReadConsoleW"),
                createNameTable(0x390, "IsValidLocale"),
                createNameTable(0x159, "EnumSystemLocalesW"),
                createNameTable(0x315, "GetTimeZoneInformation"),
                createNameTable(0x1A5, "FlushFileBuffers"),
                createNameTable(0x1F0, "GetConsoleCP"),
                createNameTable(0x531, "SetFilePointerEx"),
                createNameTable(0x253, "GetFileSizeEx"),
                createNameTable(0x38E, "IsValidCodePage"),
                createNameTable(0x29E, "GetOEMCP"),
                createNameTable(0x355, "HeapReAlloc"),
                createNameTable(0x181, "FindFirstFileExW"),
                createNameTable(0x1DC, "GetCommandLineA"),
                createNameTable(0x1DD, "GetCommandLineW"),
                createNameTable(0x23E, "GetEnvironmentStringsW"),
                createNameTable(0x1B0, "FreeEnvironmentStringsW"),
                createNameTable(0x522, "SetEnvironmentVariableW"),
                createNameTable(0x4DF, "RtlUnwind"),
                createNameTable(0x2BB, "GetProcessHeap"),
                createNameTable(0x557, "SetStdHandle"),
                createNameTable(0x357, "HeapSize"),
                createNameTable(0x51E, "SetEndOfFile"),
                createNameTable(0x620, "WriteConsoleW"),
                createNameTable(0x2EA, "GetSystemInfo")
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0x38A, "ShowCursor"),
                createNameTable(0x67, "CreateDialogIndirectParamW"),
                createNameTable(0x298, "MonitorFromRect"),
                createNameTable(0x3A8, "TrackMouseEvent"),
                createNameTable(0x124, "GetCapture"),
                createNameTable(0x35E, "SetRectEmpty"),
                createNameTable(0xB, "AppendMenuW"),
                createNameTable(0x300, "RegisterWindowMessageW"),
                createNameTable(0x5F, "CreateCursor"),
                createNameTable(0xAE, "DestroyCursor"),
                createNameTable(0x311, "ScrollWindow"),
                createNameTable(0x1AB, "GetPropW"),
                createNameTable(0x308, "RemovePropW"),
                createNameTable(0x260, "LoadStringW"),
                createNameTable(0x216, "InsertMenuItemW"),
                createNameTable(0xF, "BeginDeferWindowPos"),
                createNameTable(0xA7, "DeferWindowPos"),
                createNameTable(0xEF, "EndDeferWindowPos"),
                createNameTable(0x249, "KillTimer"),
                createNameTable(0x125, "GetCaretBlinkTime"),
                createNameTable(0xA, "AppendMenuA"),
                createNameTable(0x185, "GetMessageTime"),
                createNameTable(0x166, "GetKeyboardLayout"),
                createNameTable(0x3D4, "ValidateRect"),
                createNameTable(0x36E, "SetTimer"),
                createNameTable(0x29B, "MsgWaitForMultipleObjects"),
                createNameTable(0x29E, "NotifyWinEvent"),
                createNameTable(0x1CF, "GetUpdateRgn"),
                createNameTable(0x39D, "SystemParametersInfoA"),
                createNameTable(0x14F, "GetDoubleClickTime"),
                createNameTable(0xDA, "DrawTextA"),
                createNameTable(0x59, "CopyImage"),
                createNameTable(0x297, "MonitorFromPoint"),
                createNameTable(0x3, "AdjustWindowRectEx"),
                createNameTable(0x25F, "LoadStringA"),
                createNameTable(0x5D, "CreateAcceleratorTableW"),
                createNameTable(0x28D, "MessageBoxA"),
                createNameTable(0x1F0, "GetWindowTextLengthW"),
                createNameTable(0x3A9, "TrackPopupMenu"),
                createNameTable(0x115, "FlashWindowEx"),
                createNameTable(0x2E4, "RegisterClassExW"),
                createNameTable(0x3BA, "UnregisterClassW"),
                createNameTable(0x2B8, "PostQuitMessage"),
                createNameTable(0x3AF, "TranslateMessage"),
                createNameTable(0x186, "GetMessageW"),
                createNameTable(0x12, "BringWindowToTop"),
                createNameTable(0x301, "ReleaseCapture"),
                createNameTable(0x321, "SetCapture"),
                createNameTable(0x119, "GetActiveWindow"),
                createNameTable(0x1E, "CallNextHookEx"),
                createNameTable(0x3B4, "UnhookWindowsHookEx"),
                createNameTable(0x387, "SetWindowsHookExW"),
                createNameTable(0x351, "SetParent"),
                createNameTable(0x2E0, "RedrawWindow"),
                createNameTable(0x14A, "GetDlgCtrlID"),
                createNameTable(0x226, "IsChild"),
                createNameTable(0x112, "FindWindowExW"),
                createNameTable(0x242, "IsWindowEnabled"),
                createNameTable(0x120, "GetAsyncKeyState"),
                createNameTable(0x129, "GetClassInfoExW"),
                createNameTable(0x34D, "SetMenuItemInfoW"),
                createNameTable(0x217, "InsertMenuW"),
                createNameTable(0x17A, "GetMenuItemCount"),
                createNameTable(0xE8, "EnableMenuItem"),
                createNameTable(0x42, "CheckMenuItem"),
                createNameTable(0xB1, "DestroyMenu"),
                createNameTable(0x71, "CreatePopupMenu"),
                createNameTable(0x70, "CreateMenu"),
                createNameTable(0x17F, "GetMenuState"),
                createNameTable(0xE7, "EmptyClipboard"),
                createNameTable(0x329, "SetClipboardData"),
                createNameTable(0x240, "IsWindow"),
                createNameTable(0x14C, "GetDlgItemInt"),
                createNameTable(0x116, "FrameRect"),
                createNameTable(0x69, "CreateDialogParamW"),
                createNameTable(0x204, "InflateRect"),
                createNameTable(0x1BD, "GetSysColor"),
                createNameTable(0x4C, "ClientToScreen"),
                createNameTable(0x246, "IsWindowVisible"),
                createNameTable(0x38F, "ShowWindow"),
                createNameTable(0x227, "IsClipboardFormatAvailable"),
                createNameTable(0x2E7, "RegisterClipboardFormatW"),
                createNameTable(0x181, "GetMenuStringW"),
                createNameTable(0x24, "ChangeClipboardChain"),
                createNameTable(0x32A, "SetClipboardViewer"),
                createNameTable(0x4E, "CloseClipboard"),
                createNameTable(0x2A5, "OpenClipboard"),
                createNameTable(0x251, "LoadCursorW"),
                createNameTable(0x18D, "GetParent"),
                createNameTable(0x323, "SetCaretPos"),
                createNameTable(0x389, "ShowCaret"),
                createNameTable(0x12F, "GetClassNameA"),
                createNameTable(0xAD, "DestroyCaret"),
                createNameTable(0x5E, "CreateCaret"),
                createNameTable(0x32D, "SetCursor"),
                createNameTable(0x28C, "MessageBeep"),
                createNameTable(0x38C, "ShowScrollBar"),
                createNameTable(0x1B8, "GetScrollRange"),
                createNameTable(0x361, "SetScrollRange"),
                createNameTable(0x1B7, "GetScrollPos"),
                createNameTable(0x360, "SetScrollPos"),
                createNameTable(0x141, "GetDC"),
                createNameTable(0x3C9, "UpdateWindow"),
                createNameTable(0xDC, "DrawTextExW"),
                createNameTable(0x174, "GetMenu"),
                createNameTable(0x1C1, "GetSystemMetrics"),
                createNameTable(0x3A4, "ToAscii"),
                createNameTable(0x16A, "GetKeyboardState"),
                createNameTable(0x154, "GetFocus"),
                createNameTable(0x37D, "SetWindowPlacement"),
                createNameTable(0x1E8, "GetWindowPlacement"),
                createNameTable(0xB4, "DestroyWindow"),
                createNameTable(0x75, "CreateWindowExW"),
                createNameTable(0x2E5, "RegisterClassW"),
                createNameTable(0x2B7, "PostMessageW"),
                createNameTable(0xD3, "DrawFrameControl"),
                createNameTable(0x3AD, "TranslateAcceleratorW"),
                createNameTable(0xAC, "DestroyAcceleratorTable"),
                createNameTable(0x248, "IsZoomed"),
                createNameTable(0x22E, "IsIconic"),
                createNameTable(0x296, "ModifyMenuW"),
                createNameTable(0x17B, "GetMenuItemID"),
                createNameTable(0x223, "IsCharLowerW"),
                createNameTable(0x220, "IsCharAlphaNumericW"),
                createNameTable(0x221, "IsCharAlphaW"),
                createNameTable(0x30, "CharLowerW"),
                createNameTable(0x3E, "CharUpperW"),
                createNameTable(0xD4, "DrawIcon"),
                createNameTable(0x1BC, "GetSubMenu"),
                createNameTable(0x306, "RemoveMenu"),
                createNameTable(0x15B, "GetIconInfo"),
                createNameTable(0x14D, "GetDlgItemTextA"),
                createNameTable(0x25D, "LoadMenuW"),
                createNameTable(0x22A, "IsDialogMessageW"),
                createNameTable(0x347, "SetMenu"),
                createNameTable(0x188, "GetMonitorInfoW"),
                createNameTable(0x299, "MonitorFromWindow"),
                createNameTable(0x43, "CheckMenuRadioItem"),
                createNameTable(0x49, "ChildWindowFromPointEx"),
                createNameTable(0x33D, "SetForegroundWindow"),
                createNameTable(0x34B, "SetMenuItemBitmaps"),
                createNameTable(0xAA, "DeleteMenu"),
                createNameTable(0x6D, "CreateIconIndirect"),
                createNameTable(0x253, "LoadIconW"),
                createNameTable(0x144, "GetDesktopWindow"),
                createNameTable(0x3E5, "WindowFromPoint"),
                createNameTable(0x263, "LockWindowUpdate"),
                createNameTable(0xD0, "DrawEdge"),
                createNameTable(0x33C, "SetFocus"),
                createNameTable(0x29A, "MoveWindow"),
                createNameTable(0xD5, "DrawIconEx"),
                createNameTable(0x255, "LoadImageW"),
                createNameTable(0xEE, "EnableWindow"),
                createNameTable(0x165, "GetKeyState"),
                createNameTable(0x314, "SendDlgItemMessageW"),
                createNameTable(0xF1, "EndDialog"),
                createNameTable(0xB7, "DialogBoxIndirectParamW"),
                createNameTable(0xB9, "DialogBoxParamW"),
                createNameTable(0x13B, "GetComboBoxInfo"),
                createNameTable(0x175, "GetMenuBarInfo"),
                createNameTable(0x130, "GetClassNameW"),
                createNameTable(0xF6, "EnumChildWindows"),
                createNameTable(0x1E3, "GetWindowLongW"),
                createNameTable(0x2C1, "PtInRect"),
                createNameTable(0x2A4, "OffsetRect"),
                createNameTable(0x21A, "IntersectRect"),
                createNameTable(0x10F, "FillRect"),
                createNameTable(0xD1, "DrawFocusRect"),
                createNameTable(0x288, "MapWindowPoints"),
                createNameTable(0x30E, "ScreenToClient"),
                createNameTable(0x140, "GetCursorPos"),
                createNameTable(0x1EA, "GetWindowRect"),
                createNameTable(0x132, "GetClientRect"),
                createNameTable(0x1F1, "GetWindowTextW"),
                createNameTable(0x21B, "InvalidateRect"),
                createNameTable(0xF3, "EndPaint"),
                createNameTable(0x10, "BeginPaint"),
                createNameTable(0x302, "ReleaseDC"),
                createNameTable(0x1DA, "GetWindowDC"),
                createNameTable(0xDD, "DrawTextW"),
                createNameTable(0x17D, "GetMenuItemInfoW"),
                createNameTable(0x37E, "SetWindowPos"),
                createNameTable(0xA6, "DefWindowProcW"),
                createNameTable(0x37B, "SetWindowLongPtrW"),
                createNameTable(0x1E2, "GetWindowLongPtrW"),
                createNameTable(0x383, "SetWindowTextW"),
                createNameTable(0x14E, "GetDlgItemTextW"),
                createNameTable(0x339, "SetDlgItemTextW"),
                createNameTable(0x338, "SetDlgItemTextA"),
                createNameTable(0x14B, "GetDlgItem"),
                createNameTable(0x20, "CallWindowProcW"),
                createNameTable(0x31D, "SendMessageW"),
                createNameTable(0x294, "MessageBoxW"),
                createNameTable(0x3EC, "wsprintfW"),
                createNameTable(0x11D, "GetAncestor"),
                createNameTable(0x39F, "SystemParametersInfoW"),
                createNameTable(0x35C, "SetPropW"),
                createNameTable(0x142, "GetDCEx"),
                createNameTable(0x3EA, "mouse_event"),
                createNameTable(0x337, "SetDlgItemInt"),
                createNameTable(0x1B6, "GetScrollInfo"),
                createNameTable(0x35F, "SetScrollInfo"),
                createNameTable(0x113, "FindWindowW"),
                createNameTable(0x1F8, "HideCaret"),
                createNameTable(0xD6, "DrawMenuBar"),
                createNameTable(0x24D, "LoadBitmapW"),
                createNameTable(0xB0, "DestroyIcon"),
                createNameTable(0x135, "GetClipboardData"),
                createNameTable(0x1BE, "GetSysColorBrush"),
                createNameTable(0xBC, "DispatchMessageW")
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0x17A, "DeleteDC"),
                createNameTable(0x2AE, "GetPixel"),
                createNameTable(0x13, "BitBlt"),
                createNameTable(0x323, "RestoreDC"),
                createNameTable(0x31, "CreateCompatibleDC"),
                createNameTable(0x2A7, "GetObjectW"),
                createNameTable(0x275, "GetDeviceCaps"),
                createNameTable(0x35B, "SelectObject"),
                createNameTable(0x30, "CreateCompatibleBitmap"),
                createNameTable(0x2F4, "MoveToEx"),
                createNameTable(0x2E2, "LineTo"),
                createNameTable(0x46, "CreateHatchBrush"),
                createNameTable(0x2D1, "GetTextMetricsW"),
                createNameTable(0x383, "SetROP2"),
                createNameTable(0x2B2, "GetROP2"),
                createNameTable(0x44, "CreateFontW"),
                createNameTable(0x1D1, "ExtTextOutW"),
                createNameTable(0x32A, "SaveDC"),
                createNameTable(0x2F9, "OffsetWindowOrgEx"),
                createNameTable(0x29, "CreateBitmap"),
                createNameTable(0x4E, "CreatePatternBrush"),
                createNameTable(0x300, "PatBlt"),
                createNameTable(0x366, "SetBrushOrgEx"),
                createNameTable(0x274, "GetDIBits"),
                createNameTable(0x36C, "SetDIBits"),
                createNameTable(0x1BE, "EnumFontFamiliesExW"),
                createNameTable(0x388, "SetTextAlign"),
                createNameTable(0x394, "StartDocW"),
                createNameTable(0x188, "EndDoc"),
                createNameTable(0x396, "StartPage"),
                createNameTable(0x18B, "EndPage"),
                createNameTable(0x13B, "DPtoLP"),
                createNameTable(0x2CC, "GetTextExtentPointW"),
                createNameTable(0x397, "StretchBlt"),
                createNameTable(0x22, "CombineRgn"),
                createNameTable(0x2DC, "IntersectClipRect"),
                createNameTable(0x324, "RoundRect"),
                createNameTable(0x186, "Ellipse"),
                createNameTable(0x310, "Polygon"),
                createNameTable(0x2C4, "GetTextExtentExPointA"),
                createNameTable(0x2C6, "GetTextExtentExPointW"),
                createNameTable(0x2C8, "GetTextExtentPoint32A"),
                createNameTable(0x37, "CreateDIBSection"),
                createNameTable(0x1D0, "ExtTextOutA"),
                createNameTable(0x38A, "SetTextColor"),
                createNameTable(0x363, "SetBkMode"),
                createNameTable(0x311, "Polyline"),
                createNameTable(0x359, "SelectClipRgn"),
                createNameTable(0x319, "Rectangle"),
                createNameTable(0x2C9, "GetTextExtentPoint32W"),
                createNameTable(0x2B8, "GetStockObject"),
                createNameTable(0x269, "GetClipRgn"),
                createNameTable(0x1CA, "ExcludeClipRect"),
                createNameTable(0x17D, "DeleteObject"),
                createNameTable(0x59, "CreateSolidBrush"),
                createNameTable(0x54, "CreateRectRgnIndirect"),
                createNameTable(0x53, "CreateRectRgn"),
                createNameTable(0x4F, "CreatePen"),
                createNameTable(0x43, "CreateFontIndirectW"),
                createNameTable(0x362, "SetBkColor"),
                createNameTable(0x391, "SetWindowOrgEx"),
                createNameTable(0x3F, "CreateFontA")
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0x1, "ChooseColorW"),
                createNameTable(0x15, "PrintDlgW")
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0x25B, "RegCloseKey"),
                createNameTable(0x28C, "RegOpenKeyExW"),
                createNameTable(0x299, "RegQueryValueExW"),
                createNameTable(0x20, "AllocateAndInitializeSid"),
                createNameTable(0x5F, "CheckTokenMembership"),
                createNameTable(0x134, "FreeSid"),
                createNameTable(0x264, "RegCreateKeyExW"),
                createNameTable(0x26F, "RegDeleteKeyW"),
                createNameTable(0x273, "RegDeleteValueW"),
                createNameTable(0x27A, "RegEnumKeyExW"),
                createNameTable(0x293, "RegQueryInfoKeyW"),
                createNameTable(0x2A9, "RegSetValueExW"),
                createNameTable(0x198, "IsTextUnicode"),
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0xE, "CLSIDFromProgID"),
                createNameTable(0x1D8, "RegisterDragDrop"),
                createNameTable(0x1AB, "OleInitialize"),
                createNameTable(0xB4, "DoDragDrop"),
                createNameTable(0x1C8, "OleUninitialize"),
                createNameTable(0x1D9, "ReleaseStgMedium"),
                createNameTable(0x60, "CoInitialize"),
                createNameTable(0x90, "CoUninitialize"),
                createNameTable(0x8C, "CoTaskMemFree"),
                createNameTable(0x2B, "CoCreateInstance"),
                createNameTable(0x1DB, "RevokeDragDrop")
        });

        expectedImportByNameTable.push_back(init{
                std::make_pair(0x2, std::move(std::unique_ptr<IMAGE_IMPORT_BY_NAME>{})),
                std::make_pair(0x6, std::move(std::unique_ptr<IMAGE_IMPORT_BY_NAME>{})),
        });

        expectedImportByNameTable.push_back(init{
                createNameTable(0x4D, "OpenThemeData"),
                createNameTable(0x9, "CloseThemeData"),
                createNameTable(0xD, "DrawThemeBackground"),
                createNameTable(0x25, "GetThemeBackgroundContentRect"),
                createNameTable(0x33, "GetThemePartSize"),
                createNameTable(0x2E, "GetThemeFont"),
                createNameTable(0x51, "SetWindowTheme"),
                createNameTable(0x15, "EnableThemeDialogTexture"),
                createNameTable(0x11, "DrawThemeParentBackground"),
                createNameTable(0x43, "GetThemeTransitionDuration"),
                createNameTable(0x5, "BufferedPaintRenderAnimation"),
                createNameTable(0x17, "EndBufferedAnimation"),
                createNameTable(0x0, "BeginBufferedAnimation"),
                createNameTable(0x7, "BufferedPaintStopAllAnimations"),
                createNameTable(0x14, "DrawThemeTextEx")
        });

        for (int i = 0; i < expectedImportByNameTable.size(); i++) {
            for (int j = 0; j < expectedImportByNameTable[i].size(); j++) {
                ASSERT_EQ(expectedImportByNameTable[i][j].first, importByNameTable[i][j].first);
                if (expectedImportByNameTable[i][j].second) {
                    ASSERT_EQ(expectedImportByNameTable[i][j].second->Hint, importByNameTable[i][j].second->Hint);
                    int k{};
                    while(true){
                        if (expectedImportByNameTable[i][j].second->Name[k] == '\0' && importByNameTable[i][j].second->Name[k] == '\0') {
                            break;
                        }
                        ASSERT_EQ(expectedImportByNameTable[i][j].second->Name[k], importByNameTable[i][j].second->Name[k]);
                        k++;
                    }
                } else {
                    ASSERT_EQ(importByNameTable[i][j].second, nullptr);
                }
            }
        }
    }
};