#ifndef PE_BUFFER_HPP
#define PE_BUFFER_HPP

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

//Class to hold Bytes from Portable Executable
namespace PE_BUFFER{

    class Buffer{
    
        friend class PE_PARSER::Parser;

        FRIEND_TEST(BufferTest, HexConstructor);
        FRIEND_TEST(BufferTest, OpenPEFile);
    
    protected:
        explicit Buffer(const char* fullFilePath);
        explicit Buffer(const std::vector<BYTE>& bytes);
        explicit Buffer(const std::string& hexString);

        [[nodiscard]]
        std::vector<BYTE>::iterator getBeginIter();

        [[nodiscard]]
        BYTE* getBeginAddress();

        [[nodiscard]]
        int availableToCopy();

        void cutBytes(unsigned int bytes);
        void uncutBytes(unsigned int bytes);

        void setMemoryLocation(DWORD offset);

        [[nodiscard]]
        std::vector<BYTE> getBuffer();

    private:

        std::vector<BYTE> buffer{};
        DWORD beginPtr{};
    };

};
#endif