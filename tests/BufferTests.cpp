#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <buffer.hpp>

#include <iomanip>
#include <iostream>
#include <span>
#include <Windows.h>

namespace PE_BUFFER{

    TEST(BufferTest, HexConstructor){

        std::vector<std::string> hexStrs = {"a01738", "0a0173", "", "0A"};
        std::vector<std::vector<BYTE>> expectedBuffers = {{0xa0, 0x17, 0x38}, {0x0a, 0x01, 0x73}, {}, {0x0a}};

        for(int i = 0; i < hexStrs.size(); i++) {
            ASSERT_THAT(
                PE_BUFFER::Buffer(hexStrs[i]).getBuffer(),
                ::testing::ElementsAreArray(expectedBuffers[i])
            );
        }
    }

    TEST(BufferTest, OpenPEFile){
        std::vector<const char*> files{"../../tests/Test_PEs/1.exe"};

        //Only check first 50 bytes
        std::vector<std::vector<BYTE>> expectedBuffers{
            {
                0x4D, 0x5A, 0x90, 0, 0x03, 0, 0, 0, 4, 0, 0, 
                0, 0xFF, 0xFF, 0, 0, 0xB8, 0, 0, 0, 0, 0, 0, 
                0, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            }
        };

         for(int i = 0; i < files.size(); i++) {
           //std::vector<BYTE> buff = PE_BUFFER::Buffer(files[i]).getBuffer();
          // ASSERT_THAT(
              //  std::vector<BYTE>(buff.begin() + expectedBuffers[i].size(), buff.end()),
               // ::testing::ElementsAreArray(expectedBuffers[i])
          // );
        }
    }
};