#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <Parser.hpp>

#include <iomanip>
#include <iostream>
#include <tuple>
#include <Windows.h>

namespace PE_PARSER{

    TEST(ParserTest, Parse){

        PE_PARSER::Parser parser;
        PE_DATA::PEFile* peFile = parser.loadPEFileFromPath("../../tests/Test_PEs/1.exe");

        EXPECT_ANY_THROW({
            std::ignore = peFile->baseOfData();
        });

        //DosHeader byte data
        ASSERT_THAT(
            (std::vector<uint64_t>{
                peFile->magicNumber(), peFile->lastPageBytes(), peFile->pagesInFile(), peFile->relocations(),
                peFile->sizeOfHeaderInParagraphs(), peFile->minimumExtraParagraphs(), peFile->maximumExtraParagraphs(),
                peFile->initialSSValue(), peFile->initialSPValue(), peFile->checkSum(), peFile->initialIPValue(),
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
    }   

};