#include "Parser.hpp"

namespace PE_PARSER{

    Parser::Parser() {
        this->isBigEndian = isBigEndianCheck(); //todo: determine it by file instead
    }

    //TODO: Smart Pointer
    void Parser::freeBuffer(){
        if(this->buffer)
            free(this->buffer);
        this->buffer = nullptr;
    }

    Parser::~Parser(){
        this->freeBuffer();
    }

    template<typename Base, class Md = boost::describe::describe_members<Base, boost::describe::mod_any_access>>
    void Parser::copyBytesToStruct(Base& base){
        boost::mp11::mp_for_each<Md>([&](auto attr){
            this->copyBytesToStructInner(base.*attr.pointer);   
        });
    }

    template<typename Arr> void Parser::copyBytesToStructInnerArr(Arr& arr) {
        for (auto& el : arr){
            this->copyBytesToStructInner(el);
        }
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
            int bytesToGet = sizeof(Attr);

            if (this->buffer->availableToCopy() < bytesToGet) {
                std::string typeName = boost::typeindex::type_id_with_cvr<Attr>().pretty_name();
                std::cerr << "No more remaining data in buffer to read " + typeName;
                return;
            }

            if(this->isBigEndian){
                memcpy(&attr, this->buffer->getBeginAddress(), bytesToGet);
            }
            else{
                this->revmemcpy(&attr, this->buffer->getBeginAddress(), bytesToGet);
            } 
                
            this->buffer->cutBytes(bytesToGet);
        }
    }

    PE_DATA::PEFile* Parser::loadPEFile() {
        PE_DATA::PEFile* peFile = new PE_DATA::PEFile();
        this->copyBytesToStruct(peFile->dosHeader);
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

    bool Parser::isBigEndianCheck(void){
        union {
            uint32_t i;
            char c[4];
        } bint = { 0x01020304 };

        return bint.c[0] == 1;
    }

    //TODO: Optimize this, it's better to copy 2,4,8 bytes instead of 1 if possible
    void* Parser::revmemcpy(void* dest, const void* src, size_t len){
        uint8_t* d = (uint8_t*)dest + len - 1;
        uint8_t* s = (uint8_t*)src;
        while (len--)
            *d-- = *s++;
        return dest;
    }
};