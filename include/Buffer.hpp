#ifndef BUFFER_H
#define BUFFER_H

#include <vector>
#include <windows.h>
#include <istream>
#include <fstream>
#include <iostream>

#include <boost/algorithm/hex.hpp>

#include <gtest/gtest_prod.h>

namespace PE_PARSER{
    class Parser;
};

namespace PE_BUFFER{

    class Buffer{
    
        friend class PE_PARSER::Parser;

        FRIEND_TEST(BufferTest, HexConstructor);
        FRIEND_TEST(BufferTest, OpenPEFile);
    
    protected:
        Buffer(const char* fullFilePath);
        Buffer(std::vector<BYTE> bytes);
        Buffer(const std::string& hexString); 

        [[nodiscard]]
        std::vector<BYTE>::iterator getBeginIter();

        [[nodiscard]]
        BYTE* getBeginAddress();

        [[nodiscard]]
        int availableToCopy();

        void cutBytes(int bytes);

        [[nodiscard]]
        std::vector<BYTE> getBuffer();

    private:

        std::vector<BYTE> buffer{};
        int beginPtr{};
    };

};

#endif