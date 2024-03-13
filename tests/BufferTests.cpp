#include <gtest/gtest.h>
#include <buffer.hpp>

#include <Windows.h>

TEST(BufferTest, PathConstructor) {

}

TEST_F(BufferTest, HexConstructor) {

    std::vector<std::string> hexStrs = {"a01738", "a0173"};
    std::vector<std::vector<BYTE>> expectedBuffers = {{160, 23, 56}, {10, 1, 115}};

    for(int i = 0; i < hexStrs.size(); i++) {
        PE_BUFFER::Buffer buff = PE_BUFFER::Buffer(hexStrs[i]);
        
        std::vector<BYTE> outBuff = buff.getBuffer();

        EXPECT_EQ(outBuff.size(), expectedBuffers[i].size()) << "Buffer has wrong size!";
        
        for (int j = 0; j < outBuff.size(); ++j) {
            EXPECT_EQ(outBuff[j], expectedBuffers[i][j]) << "Buffer has wrong value at index " << i;
        }
    }
}

TEST(BufferTest, AvailableToCopyTest){

}

TEST(BufferTest, BeginTest){


}

TEST(BufferTest, CutTest){


}