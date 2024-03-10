#ifndef BUFFER_H
#define BUFFER_H

#include <vector>
#include <windows.h>

namespace PE_BUFFER{

    class Buffer{
    public:
        //todo: move constructor
        Buffer(std::vector<BYTE> buffer);

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