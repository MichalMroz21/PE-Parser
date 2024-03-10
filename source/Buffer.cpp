#include "Buffer.hpp"

namespace PE_BUFFER{

    Buffer::Buffer(std::vector<BYTE> buffer){
        this->buffer = buffer;
    }

    void Buffer::cutBytes(int bytes){
        this->beginPtr += bytes;
    }

    std::vector<BYTE>::iterator Buffer::getBegin(){
        if(this->beginPtr < this->buffer.size())
            return this->buffer.begin() + this->beginPtr;

        else return this->buffer.end();
    }

    int Buffer::getBeginPtr(){
        return this->beginPtr;
    }

    int Buffer::availableToCopy(){
        return std::distance(getBegin(), this->buffer.end());
    }

};