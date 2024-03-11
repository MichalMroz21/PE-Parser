#include "Buffer.hpp"

namespace PE_BUFFER{

    Buffer::Buffer(const char* fullPEPath){
        std::ifstream peFile(fullPEPath, std::ios::binary);

        if (!peFile.is_open()) {
            throw std::runtime_error("Error opening PE file: " + std::string(fullPEPath));
        }

        this->buffer = std::vector<BYTE>((std::istreambuf_iterator<char>(peFile)), std::istreambuf_iterator<char>());
    }

    Buffer::Buffer(std::vector<BYTE> bytes){
        this->buffer = bytes;
    }
    
    Buffer::Buffer(const std::string& hexString){

    }

    std::vector<BYTE>::iterator Buffer::getBeginIter(){
        if(this->availableToCopy() > 0)
            return this->buffer.begin() + this->beginPtr;

        return this->buffer.end();
    }

    BYTE* Buffer::getBeginAddress(){
        if(this->availableToCopy() > 0)
            return this->buffer.data() + this->beginPtr;

        return this->buffer.data() + this->buffer.size();
    }

    int Buffer::availableToCopy(){
        return this->buffer.size() - this->beginPtr;
    }

    void Buffer::cutBytes(int bytes){
        this->beginPtr += bytes;
    }
};