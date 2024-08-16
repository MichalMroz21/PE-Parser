#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "PE-Parser/Converter.hpp"
#include "PE-Parser/Parser.hpp"

#include <tuple>
#include <vector>
#include <string>

namespace PE_CONVERTER{

    TEST(ConverterTest, Convert){

        PE_PARSER::Parser parser;
        PE_DATA::PEFile* peFile = parser.loadPEFileFromPath("D:/PE-Parser/tests/Test_PEs/1.exe");

        Converter converter;

        ASSERT_EQ(converter.getMachineStr(peFile->machine()), "AMD64 (K8)");
        ASSERT_EQ(converter.getTimestampStr(peFile->timeDateStamp()), "26.09.2021-13:26:03-UTC");
        ASSERT_EQ(converter.getMagicValue(peFile->magic()), "PE32+");
        ASSERT_EQ(converter.getSubsystem(peFile->subsystem()), "The Windows graphical user interface (GUI) subsystem");

        ASSERT_THAT(
            converter.getCharacteristics(peFile->characteristics()),
            ::testing::ElementsAreArray(
                std::vector<std::string>{
                    "Image only. The image file is valid and can be run.",
                    "Application can handle > 2-GB addresses."
                }
            )
        );

        ASSERT_THAT(
            converter.getDllCharacteristics(peFile->dllCharacteristics()),
            ::testing::ElementsAreArray(
                std::vector<std::string>{
                    "Image can handle a high entropy 64-bit virtual address space.",
                    "DLL can be relocated at load time.",
                    "Image is NX compatible.",
                    "Terminal Server aware."
                }
            )
        );
    }

};