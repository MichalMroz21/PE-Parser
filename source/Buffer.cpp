#include <Buffer.hpp>

namespace PE_BUFFER{

    Buffer::Buffer(const char* fullPEPath){
        std::ifstream peFile(fullPEPath, std::ifstream::binary | std::ifstream::ate);

        if (!peFile.is_open()) {
            throw std::runtime_error("Error opening PE file: " + std::string(fullPEPath));
        }

        peFile.exceptions(std::ifstream::failbit | std::ifstream::badbit);

        std::ifstream::pos_type size = peFile.tellg();
        peFile.seekg(0, std::ios::beg);

        this->buffer.resize(size);

        peFile.read(reinterpret_cast<char*>(this->buffer.data()), size);
        peFile.close();
    }

    Buffer::Buffer(const std::vector<BYTE>& bytes){
        this->buffer = bytes;
    }
    
    //hexString has to be of even size
    Buffer::Buffer(const std::string& hexString){
        if (hexString.size() % 2) {
            throw std::invalid_argument("Hex String for Buffer is not of even size");
        }

        boost::algorithm::unhex(hexString, std::back_inserter(this->buffer));
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

    void Buffer::cutBytes(unsigned int bytes){
        this->beginPtr += bytes;
    }

    void Buffer::uncutBytes(unsigned int bytes){
        this->beginPtr -= bytes;
    }

    void Buffer::setMemoryLocation(DWORD offset){
        this->beginPtr = offset;
    }

    std::vector<BYTE> Buffer::getBuffer(){
        return this->buffer;
    }
};