#include "Buffer.hpp"

namespace PE_BUFFER{

    Buffer::Buffer(std::vector<BYTE> bytes){
        this->buffer = bytes;
    }

    Buffer::Buffer(const char* fullPEPath){
        std::ifstream peFile(fullPEPath, std::ios::binary);

        if (!peFile.is_open()) {
            throw std::runtime_error("Error opening PE file: " + std::string(fullPEPath));
        }

        this->buffer = std::vector<BYTE>((std::istreambuf_iterator<char>(peFile)), std::istreambuf_iterator<char>());
    }
    
    Buffer::Buffer(const std::string& hexString){

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