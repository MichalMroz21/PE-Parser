#include "Parser.hpp"

namespace PE_PARSER{

    Parser::Parser() {
        this->isBigEndian = isBigEndianCheck(); //todo: determine it by file instead
    }

    Parser::~Parser(){
        if(this->buffer)
            free(this->buffer);
        this->buffer = nullptr;
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

            int beginPtr = this->buffer->getBeginPtr();

            memcpy_s(this->buffer + beginPtr, this->buffer->availableToCopy(), &attr, bytesToGet);

            if(!this->isBigEndian){
                attr = boost::endian::endian_reverse(attr);
            } 
                
            this->buffer->cutBytes(bytesToGet);
        }
    }

    //bufferBeginPtr needs to be resetted everytime we load a new Binary into the Parser
    PE_DATA::PEFile* Parser::loadPEFileFromBinary(PE_BUFFER::Buffer* PEBinary) {

        this->buffer = PEBinary;

        PE_DATA::PEFile* peFile = new PE_DATA::PEFile();

        this->copyBytesToStruct(peFile->dosHeader);

        DWORD NTHeaderLoc = peFile->dosHeader.e_lfanew;

        return nullptr;
    }

    PE_DATA::PEFile* Parser::loadPEFileFromPath(const char* fullPEPath) {
        
        std::ifstream peFile(fullPEPath, std::ios::binary);

        if (!peFile.is_open()) {
            throw std::runtime_error("Error opening PE file: " + std::string(fullPEPath));
        }

        return this->loadPEFileFromBinary(
            new PE_BUFFER::Buffer(
                std::vector<BYTE>((std::istreambuf_iterator<char>(peFile)), std::istreambuf_iterator<char>())
            )
        );
    }

    bool Parser::isBigEndianCheck(void) {
        union {
            uint32_t i;
            char c[4];
        } bint = { 0x01020304 };

        return bint.c[0] == 1;
    }

};