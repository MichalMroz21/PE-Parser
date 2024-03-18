#ifndef PARSER
#define PARSER

#include <vector>
#include <stdint.h>
#include <windows.h>
#include <fstream>
#include <iostream>
#include <cstring>
#include <string>
#include <type_traits>
#include <bit>

#include <boost/mp11.hpp>
#include <boost/type_index.hpp>
#include <boost/describe.hpp>
#include <boost/endian/conversion.hpp>

#include <PEFile.hpp>
#include <Structure.hpp>
#include <Buffer.hpp>

namespace PE_PARSER{

    class Parser {
    public:

        Parser();
        ~Parser();

        [[nodiscard]]
        PE_DATA::PEFile* loadPEFileFromPath(const char* fullPEPath);

        [[nodiscard]]
        PE_DATA::PEFile* loadPEFileFromBytes(std::vector<BYTE> bytes);

        //hexString has to be of even size
        [[nodiscard]]
        PE_DATA::PEFile* loadPEFileFromHexString(const std::string& hexStr);
        
    private:
        PE_DATA::PEFile* loadPEFile();

        //returns amount of bytes copied to struct
        template<typename Base, class Md = boost::describe::describe_members<Base, boost::describe::mod_any_access>>
        void copyBytesToStruct(Base& base);

        template<typename Attr> 
        void copyBytesToStructInner(Attr& attr);

        template<typename Arr> 
        void copyBytesToStructInnerArr(Arr& arr);

        template<typename Attr> 
        void copyBytesToVariable(Attr& attr);
        
        void freeBuffer();
        void* revmemcpy(void* dest, const void* src, size_t len);

        PE_BUFFER::Buffer* buffer{};
        
        static constexpr bool isBigEndian = (std::endian::native == std::endian::big); 
    };

};
#endif