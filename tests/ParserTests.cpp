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
    }   

};