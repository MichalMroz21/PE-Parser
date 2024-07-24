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

    //Buffer's library functions
    //To obtain a buffer pointer, set a flag not to freeBuffer in Parser to false and use a method after parsing.
    public:
        void cutBytes(unsigned int bytes); //adds to buffer's pointer
        void uncutBytes(unsigned int bytes); //subtracts from buffer's pointer
        void setMemoryLocation(DWORD offset); //sets buffer at offset

        [[nodiscard]] std::vector<BYTE>::iterator getBeginIter(); //returns iterator to buffer
        [[nodiscard]] std::vector<BYTE> getBuffer(); //returns buffer
        [[nodiscard]] BYTE* getBeginAddress(); //returns pointer to buffer
        [[nodiscard]] int availableToCopy(); //returns how many bytes are left in the buffer
        [[nodiscard]] DWORD getCurrMemoryLocation(); //obtains current offset

    protected:
        explicit Buffer(const char* fullFilePath);
        explicit Buffer(const std::vector<BYTE>& bytes);
        explicit Buffer(const std::string& hexString);

    private:
        std::vector<BYTE> buffer{};
        DWORD beginPtr{};
    };
};
#endif