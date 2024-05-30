#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <Parser.hpp>

#include <tuple>
#include <winnt.h>

namespace PE_PARSER{
    std::unique_ptr<IMAGE_IMPORT_BY_NAME> createImageImportByName(WORD hint, const char* name){
        size_t nameLength = std::strlen(name) + 1; // +1 for null terminator
        size_t totalSize = sizeof(IMAGE_IMPORT_BY_NAME) + nameLength - 1; // -1 because Name[1] already accounts for one char

        auto importByName = std::unique_ptr<IMAGE_IMPORT_BY_NAME>((IMAGE_IMPORT_BY_NAME*)malloc(totalSize));

        std::memcpy(importByName->Name, name, nameLength);
        importByName->Hint = hint;

        return importByName;
    }

    std::pair<std::optional<WORD>, std::unique_ptr<IMAGE_IMPORT_BY_NAME>> createNameTable(std::optional<WORD> ordinal, WORD hint, const char* name){
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

        //ImportByNameTable byte data
        std::vector<std::vector<std::pair<std::optional<WORD>, std::unique_ptr<IMAGE_IMPORT_BY_NAME>>>> importByNameTable = std::move(*peFile->getImportByNameTable());
        std::vector<std::vector<std::pair<std::optional<WORD>, std::unique_ptr<IMAGE_IMPORT_BY_NAME>>>> expectedImportByNameTable = {
                {
                        createNameTable(std::nullopt, 0x51, "ImageList_BeginDrag"),
                        createNameTable(std::nullopt, 0x5F, "ImageList_EndDrag"),
                        createNameTable(std::nullopt, 0x76, "ImageList_SetIconSize"),
                        createNameTable(std::nullopt, 0x59, "ImageList_DragMove"),
                        createNameTable(std::nullopt, 0x5A, "ImageList_DragShowNolock"),
                        std::make_pair(0x11, std::move(std::unique_ptr<IMAGE_IMPORT_BY_NAME>{})),
                        createNameTable(std::nullopt, 0x50, "ImageList_AddMasked"),
                        createNameTable(std::nullopt, 0x65, "ImageList_GetImageCount"),
                        createNameTable(std::nullopt, 0x7C, "InitCommonControlsEx"),
                        createNameTable(std::nullopt, 0x70, "ImageList_ReplaceIcon"),
                        createNameTable(std::nullopt, 0x55, "ImageList_Destroy"),
                        createNameTable(std::nullopt, 0x54, "ImageList_Create"),
                        createNameTable(std::nullopt, 0x93, "_TrackMouseEvent"),
                        createNameTable(std::nullopt, 0x66, "ImageList_GetImageInfo"),
                        createNameTable(std::nullopt, 0x5B, "ImageList_Draw"),
                        std::make_pair(0x19D, std::move(std::unique_ptr<IMAGE_IMPORT_BY_NAME>{})),
                        std::make_pair(0x19C, std::move(std::unique_ptr<IMAGE_IMPORT_BY_NAME>{})),
                        createNameTable(std::nullopt, 0x57, "ImageList_DragEnter"),
                        std::make_pair(0x19A, std::move(std::unique_ptr<IMAGE_IMPORT_BY_NAME>{}))
                }};
       }
};