#ifndef BUFFER_H
#define BUFFER_H

#include <vector>
#include <windows.h>
#include <fstream>

namespace PE_BUFFER{

    class Buffer{
    public:
        Buffer(std::vector<BYTE> bytes);
        Buffer(const std::string& hexString);
        Buffer(const char* fullFilePath);

        void cutBytes(int bytes);

        [[nodiscard]]
        std::vector<BYTE>::iterator getBegin();

        [[nodiscard]]
        int getBeginPtr();

        [[nodiscard]]
        int availableToCopy();

    private:
        std::vector<BYTE> buffer{};
        int beginPtr{};
    };

};

#endif