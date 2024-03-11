#ifndef BUFFER_H
#define BUFFER_H

#include <vector>
#include <windows.h>
#include <fstream>

namespace PE_PARSER{
    class Parser;
};

namespace PE_BUFFER{

    class Buffer{
    
        friend class PE_PARSER::Parser;
    
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

    private:
        std::vector<BYTE> buffer{};
        int beginPtr{};
    };

};

#endif