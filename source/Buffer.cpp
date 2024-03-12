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
        int n = hexString.size();
        this->buffer = std::vector<BYTE>(n / 2);

        for(int i = 0; i < n; i += 2){
            std::string strByte = hexString.substr(i, 2);
            if(i == 0 && n % 2) {
                i--;
                std::swap(strByte[0], strByte[1]);
                strByte[0] = '0';
            }
            this->buffer[i / 2] = std::stoi(strByte, nullptr, 16);
        }
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

    std::vector<BYTE> Buffer::getBuffer(){
        return this->buffer;
    }
};