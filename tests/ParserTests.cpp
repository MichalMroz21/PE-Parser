#include <gtest/gtest.h>
#include <parser.hpp>

#include <iomanip>
#include <iostream>
#include <Windows.h>

namespace PE_PARSER{

    TEST(ParserTest, Parse){

        PE_PARSER::Parser parser;

        PE_DATA::PEFile* peFile = parser.loadPEFileFromPath("../../tests/Test_PEs/1.exe");

        //DosHeader data
        EXPECT_EQ(peFile->magicNumber(), 0x5A4D);
        EXPECT_EQ(peFile->lastPageBytes(), 0x0090);
        EXPECT_EQ(peFile->pagesInFile(), 0x0003);
        EXPECT_EQ(peFile->relocations(), 0x0000);
        EXPECT_EQ(peFile->sizeOfHeaderInParagraphs(), 0x0004);
        EXPECT_EQ(peFile->minimumExtraParagraphs(), 0x00000);
        EXPECT_EQ(peFile->maximumExtraParagraphs(), 0xFFFF);
        EXPECT_EQ(peFile->initialSSValue(), 0x0000);
        EXPECT_EQ(peFile->initialSPValue(), 0x00B8);
        EXPECT_EQ(peFile->checkSum(), 0x0000);
        EXPECT_EQ(peFile->initialIPValue(), 0x0000);
        EXPECT_EQ(peFile->initialCSValue(), 0x0000);
        EXPECT_EQ(peFile->addressRelocationTable(), 0x0040);
        EXPECT_EQ(peFile->overlayNumber(), 0x0000);
        EXPECT_EQ(peFile->oemIdentifier(), 0x0000);
        EXPECT_EQ(peFile->oemInformation(), 0x000);
        EXPECT_EQ(peFile->headerAddress(), 0x00000128);

        //ImageHeader data
        EXPECT_EQ(peFile->signature(), 0x00004550);
        EXPECT_EQ(peFile->machine(), 0x8664);
        EXPECT_EQ(peFile->numberOfSections(), 0x0006);
        EXPECT_EQ(peFile->timeDateStamp(), 0x615074eb);
        EXPECT_EQ(peFile->pointerToSymbolTable(), 0x00000000);
        EXPECT_EQ(peFile->numberOfSymbols(), 0x00000000);
        EXPECT_EQ(peFile->sizeOfOptionalHeader(), 0x00F0);
        EXPECT_EQ(peFile->charasteristics(), 0x0022);

        //OptionalHeader data
        EXPECT_EQ(peFile->magic(), 0x020B);
        EXPECT_EQ(peFile->majorLinkerVersion(), 0x0E);
        EXPECT_EQ(peFile->minorLinkerVersion(), 0x10);
        EXPECT_EQ(peFile->sizeOfCode(), 0x00333400);
        EXPECT_EQ(peFile->sizeOfInitializedData(), 0x0029FE00);
        EXPECT_EQ(peFile->sizeOfUninitializedData(), 0x00000000);
        EXPECT_EQ(peFile->addressOfEntryPoint(), 0x002CD4B4);
        EXPECT_EQ(peFile->baseOfCode(), 0x00001000);
        EXPECT_EQ(peFile->baseOfData(), 0x00000200);
        EXPECT_EQ(peFile->imageBase(), 0x0000000140000000);
        EXPECT_EQ(peFile->sectionAlignment(), 0x00001000);
        EXPECT_EQ(peFile->fileAlignment(), 0x00000200);
        EXPECT_EQ(peFile->majorOperatingSystemVersion(), 0x0005);
        EXPECT_EQ(peFile->minorOperatingSystemVersion(), 0x0002);
        EXPECT_EQ(peFile->majorImageVersion(), 0x0001);
        EXPECT_EQ(peFile->minorImageVersion(), 0x0000);
        EXPECT_EQ(peFile->majorSubsystemVersion(), 0x0005);
        EXPECT_EQ(peFile->minorSubsystemVersion(), 0x0002);
        EXPECT_EQ(peFile->win32VersionValue(), 0x00000000);
        EXPECT_EQ(peFile->sizeOfImage(), 0x005D8000);
        EXPECT_EQ(peFile->sizeOfHeaders(), 0x00000400);
        EXPECT_EQ(peFile->checkSum(), 0x005C561D);
        EXPECT_EQ(peFile->dllCharasteristics(), 0x00008160);
        EXPECT_EQ(peFile->sizeOfStackReserve(), 0x0000000000100000);
        EXPECT_EQ(peFile->sizeOfStackCommit(), 0x0000000000001000);
        EXPECT_EQ(peFile->sizeOfHeapReserve(), 0x0000000000100000);
        EXPECT_EQ(peFile->sizeOfHeapCommit(), 0x0000000000001000);
        EXPECT_EQ(peFile->loaderFlags(), 0x00000000);
        EXPECT_EQ(peFile->numberOfRvaAndSizes(), 0x00000010);
    }   

};