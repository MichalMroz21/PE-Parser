#include <Parser.hpp>

namespace PE_PARSER{

    Parser::Parser() {}

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
    void Parser::copyBytesToStruct(Base& base, std::size_t toCopy){
        boost::mp11::mp_for_each<Md>([&](auto attr){
            this->copyBytesToStructInner(base.*attr.pointer, toCopy);
            toCopy -= sizeof(attr);   
        });
    }

    template<typename Arr> 
    void Parser::copyBytesToStructInnerArr(Arr& arr) {
        for (auto& el : arr){
            this->copyBytesToStructInner(el);
        }
    }

    template<typename Attr> 
    void Parser::copyBytesToVariable(Attr& attr){
        int bytesToGet = sizeof(Attr);

        if (this->buffer->availableToCopy() < bytesToGet) {
            std::string typeName = boost::typeindex::type_id_with_cvr<Attr>().pretty_name();
            std::cerr << "No more remaining data in buffer to read " + typeName;
            return;
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
    void Parser::copyBytesToStructInner(Attr& attr){

        //check if iterated type is struct, if it is then recursively call this function for it
        if constexpr (std::is_class_v<Attr>){
            this->copyBytesToStruct(attr);
        }
        else if constexpr (std::is_array_v<Attr>){
            this->copyBytesToStructInnerArr(attr);
        }
        else{
            this->copyBytesToVariable(attr);
        }
    }

    PE_DATA::PEFile* Parser::loadPEFile(){
        PE_DATA::PEFile* peFile = new PE_DATA::PEFile();

        this->copyBytesToStruct(peFile->dosHeader);
        this->buffer->setMemoryLocation(peFile->headerAddress());

        this->copyBytesToStruct(peFile->imageHeader);

        DWORD stateOfMachine{};

        this->copyBytesToVariable(stateOfMachine);
        this->buffer->uncutBytes(sizeof(stateOfMachine));

        peFile->setTypeOfPE(stateOfMachine);

        int sz = peFile->sizeOfOptionalHeader();

        boost::apply_visitor([this, peFile](auto x){
            this->copyBytesToStruct(*x);
        }, peFile->getOptionalHeader());
            
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