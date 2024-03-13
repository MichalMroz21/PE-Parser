#ifndef BUFFER_H
#define BUFFER_H

#include <vector>
#include <windows.h>
#include <fstream>

#include <gtest/gtest_prod.h>

namespace PE_PARSER{
    class Parser;
};

class BufferTest_HexConstructor_Test;

namespace PE_BUFFER{

    class Buffer{
    
        friend class PE_PARSER::Parser;
        friend class BufferTest_HexConstructor_Test;
        FRIEND_TEST(BufferTest, HexConstructor);
    
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

        std::vector<BYTE> getBuffer();

    private:

        std::vector<BYTE> buffer{};
        int beginPtr{};
    };

};

#endif