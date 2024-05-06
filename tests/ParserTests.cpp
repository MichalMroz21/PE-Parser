#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <Parser.hpp>

#include <tuple>
#include <winnt.h>
#include <iostream>

namespace PE_PARSER{

    TEST(ParserTest, Parse){

        PE_PARSER::Parser parser;
        PE_DATA::PEFile* peFile = parser.loadPEFileFromPath("../../tests/Test_PEs/1.exe");

        /*EXPECT_ANY_THROW({
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
        );*/

        //DataDirectory byte data
        ASSERT_THAT(
                (std::vector<std::pair<DWORD, std::size_t>>{
                        peFile->exportDirectory(), peFile->importDirectory(), peFile->resourceDirectory(), peFile->exceptionDirectory(),
                        peFile->securityDirectory(), peFile->baseRelocationDirectory(), peFile->debugDirectory(), peFile->architectureDirectory(),
                        peFile->globalPtrDirectory(), peFile->tlsDirectory(), peFile->loadConfigDirectory(), peFile->boundImportDirectory(),
                        peFile->iatDirectory(), peFile->delayImportDescriptor(), peFile->clrRuntimeHeader()
                }),
                ::testing::ElementsAreArray(
                        std::vector<std::pair<DWORD, std::size_t>>{
                                {0, 0}, {0xDE8C8, 0xB4}, {0XE8000, 0xCBC8},
                                {0x0, 0x0}, {0xF6868, 0x2948}, {0xF5000, 0X4E88},
                                {0xD67F4, 0x54}, {0, 0}, {0, 0}, {0XD6880, 0x18}, {0xD6720, 0x40},
                                {0, 0}, {0x6B000, 0x2FC}, {0xDE774, 0x60}, {0, 0}
                        }
                )
        );

        //SectionHeaders byte data
       // ASSERT_THAT(
             //   peFile->getSectionHeaders(),
               // ::testing::ElementsAreArray(
                     //   std::vector<IMAGE_SECTION_HEADER>{
                           //     {"text", 0, 0x1000, 0x333400, 0x200, 0x0, 0x0, 0x0, 0x0, 0x60000020},
                          //      {".rdata", 0, 0x335000, 0xF7800, 0x200, 0x0, 0x0, 0x0, 0x0, 0x40000040},
                         //       {".data", 0, 0x42D000, 0x11800, 0x200, 0x0, 0x0, 0x0, 0x0, 0xC0000040},
                         //       {".pdata", 0, 0x453000, 0x1A600, 0x200, 0x0, 0x0, 0x0, 0x0, 0x40000040},
                         //       {".rsrc", 0, 0x46E000, 0x163C00, 0x200, 0x0, 0x0, 0x0, 0x0, 0x40000040},
                        //        {".reloc", 0, 0x5D2000, 0x5200, 0x200, 0x0, 0x0, 0x0, 0x0, 0x42000040}
                     //   }
             //   )
       // );
    }   

};