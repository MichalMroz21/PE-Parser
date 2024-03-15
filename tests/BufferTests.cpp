#include <gtest/gtest.h>
#include <buffer.hpp>

#include <iomanip>
#include <iostream>
#include <Windows.h>

namespace PE_BUFFER{

    TEST(BufferTest, HexConstructor){

        std::vector<std::string> hexStrs = {"a01738", "0a0173", "", "0A"};
        std::vector<std::vector<BYTE>> expectedBuffers = {{160, 23, 56}, {10, 1, 115}, {}, {10}};

        for(int i = 0; i < hexStrs.size(); i++) {
            PE_BUFFER::Buffer buff = PE_BUFFER::Buffer(hexStrs[i]);
            
            std::vector<BYTE> outBuff = buff.getBuffer();

            EXPECT_EQ(outBuff.size(), expectedBuffers[i].size()) << "Buffer has wrong size!";
            
            for (int j = 0; j < outBuff.size(); ++j) {
                EXPECT_EQ(outBuff[j], expectedBuffers[i][j]) << "Buffer has wrong value at index " << i;
            }
        }
    }

    TEST(BufferTest, OpenPEFile){
        std::vector<const char*> files{"../../tests/Test_PEs/1.exe"};
        //Only checks first 50 bytes
        std::vector<std::vector<BYTE>> expectedBuffers = {{77, 90, 144, 0, 3, 0, 0, 0, 4, 0, 0, 0, 255, 255, 0, 0, 
        184, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

         for(int i = 0; i < files.size(); i++) {
            PE_BUFFER::Buffer buff = PE_BUFFER::Buffer(files[i]);
            
            std::vector<BYTE> outBuff = buff.getBuffer();

           for (int j = 0; j < expectedBuffers[i].size(); ++j) {
                EXPECT_EQ(outBuff[j], expectedBuffers[i][j]) << "Buffer has wrong value at index " << i;
           }
        }
    }
};