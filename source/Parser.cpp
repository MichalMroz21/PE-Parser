#include "Parser.hpp"

namespace PE_PARSER{

    Parser::Parser() {}

    //TODO: Smart Pointer
    void Parser::freeBuffer(){
        if(this->buffer)
            free(this->buffer);
        this->buffer = nullptr;
    }

    Parser::~Parser(){
        this->freeBuffer();
    }   

    template<typename Base>
    void Parser::copyBytesToStruct(Base* structPtr){
        if(!structPtr) return;

        int bytesToCopy = std::min(static_cast<int>(sizeof(Base)), this->buffer->availableToCopy());
        std::memcpy(structPtr, this->buffer->getBeginAddress(), bytesToCopy);
        this->buffer->cutBytes(bytesToCopy);
    }

    PE_DATA::PEFile* Parser::loadPEFile() {
        PE_DATA::PEFile* peFile = new PE_DATA::PEFile();
        this->copyBytesToStruct(&peFile->dosHeader);
        
        DWORD NTHeaderLoc = peFile->dosHeader.e_lfanew;

        return peFile;
    }

    PE_DATA::PEFile* Parser::loadPEFileFromPath(const char* fullPEPath){
        this->freeBuffer();
        this->buffer = new PE_BUFFER::Buffer(fullPEPath);
        return this->loadPEFile();
    }

    PE_DATA::PEFile* Parser::loadPEFileFromBytes(std::vector<BYTE> bytes){
        this->freeBuffer();
        this->buffer = new PE_BUFFER::Buffer(bytes);
        return this->loadPEFile();
    }

    PE_DATA::PEFile* Parser::loadPEFileFromHexString(const std::string& hexStr){
        this->freeBuffer();
        this->buffer = new PE_BUFFER::Buffer(hexStr);
        return this->loadPEFile();
    }
};