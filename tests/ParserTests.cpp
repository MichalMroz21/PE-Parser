#include <gtest/gtest.h>
#include <parser.hpp>

#include <iomanip>
#include <iostream>
#include <Windows.h>

namespace PE_PARSER{

    TEST(ParserTest, Parse){

        PE_PARSER::Parser parser;

        PE_DATA::PEFile* peFile = parser.loadPEFileFromPath("../../tests/Test_PEs/1.exe");

        EXPECT_EQ(peFile->dosHeader.magic, 0x4D5A);
        EXPECT_EQ(peFile->dosHeader.e_lfanew, 0x28010000);

    }

};