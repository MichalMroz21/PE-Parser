#include <Parser.hpp>

namespace PE_PARSER{

    Parser::Parser() = default;

    void Parser::freeBuffer(){
        if(this->buffer)
            free(this->buffer);
        this->buffer = nullptr;
    }

    Parser::~Parser(){
        freeBuffer();
    }

    //using this instead of memcpy with struct, because in case of big endian recursive struct iteration is needed
    template<typename Base, class Md>
    void Parser::copyBytesToStruct(Base& base, int toCopy){
        boost::mp11::mp_for_each<Md>([&](auto attr){
            if(toCopy <= 0) return;
            this->copyBytesToStructInner(base.*attr.pointer, toCopy);
            toCopy -= sizeof(attr);   
        });
    }

    template<typename Arr> 
    void Parser::copyBytesToStructInnerArr(Arr& arr, int toCopy) {
        for (auto& el : arr){
            if(toCopy <= 0) return;
            this->copyBytesToStructInner(el, toCopy);
            toCopy -= sizeof(el);
        }
    }

    template<typename Attr> 
    void Parser::copyBytesToVariable(Attr& attr){
        int bytesToGet = sizeof(Attr);

        if (this->buffer->availableToCopy() < bytesToGet) {
            throw std::logic_error("Trying to read from a buffer that has no more data to copy from");
        }

        if(!this->isBigEndian){
            memcpy(&attr, this->buffer->getBeginAddress(), bytesToGet);
        }
        else{
            std::reverse_copy(reinterpret_cast<const char*>(this->buffer->getBeginAddress()),
                reinterpret_cast<const char*>(this->buffer->getBeginAddress() + bytesToGet), reinterpret_cast<char*>(&attr));
        } 
            
        this->buffer->cutBytes(bytesToGet);
    }

    template<typename Attr> 
    void Parser::copyBytesToStructInner(Attr& attr, int toCopy){
        //check if iterated type is struct, if it is then recursively call this function for it
        if constexpr (std::is_class_v<Attr>){
            this->copyBytesToStruct(attr, toCopy);
        }
        else if constexpr (std::is_array_v<Attr>){
            this->copyBytesToStructInnerArr(attr, toCopy);
        }
        else if(toCopy >= sizeof(attr)){
            this->copyBytesToVariable(attr);
        }
    }

    PE_DATA::PEFile* Parser::loadPEFile(){
        auto* peFile = new PE_DATA::PEFile();

        this->copyBytesToStruct(peFile->dosHeader);
        this->buffer->setMemoryLocation(peFile->headerAddress());

        this->copyBytesToStruct(peFile->imageHeader);

        //Allocate space for section headers
        peFile->allocateSectionHeaders(peFile->numberOfSections());

        //The type of Optional Header
        DWORD stateOfMachine{};

        this->copyBytesToVariable(stateOfMachine);
        this->buffer->uncutBytes(sizeof(stateOfMachine));

        peFile->setTypeOfPE(stateOfMachine);

        boost::apply_visitor([this, peFile](auto x){
            this->copyBytesToStruct(*x, peFile->sizeOfOptionalHeader());
        }, peFile->getOptionalHeader());

        for(auto& imageSectionHeader : peFile->imageSectionHeaders){
            this->copyBytesToStruct(imageSectionHeader);
        }
            
        return peFile;
    }

    PE_DATA::PEFile* Parser::loadPEFileFromPath(const char* fullPEPath){
        this->freeBuffer();
        this->buffer = new PE_BUFFER::Buffer(fullPEPath);
        return this->loadPEFile();
    }

    PE_DATA::PEFile* Parser::loadPEFileFromBytes(const std::vector<BYTE>& bytes){
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