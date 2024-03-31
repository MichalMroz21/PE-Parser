#ifndef PE_PARSER_HPP
#define PE_PARSER_HPP

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

//Class for extracting bytes from Portable Executables
namespace PE_PARSER{

    class Parser {
    public:

        Parser();
        ~Parser();

        //User Entry Points into parsing Portable Executables
        [[nodiscard]]
        PE_DATA::PEFile* loadPEFileFromPath(const char* fullPEPath);

        [[nodiscard]]
        PE_DATA::PEFile* loadPEFileFromBytes(std::vector<BYTE> bytes);

        //hexString has to be of even size
        [[nodiscard]]
        PE_DATA::PEFile* loadPEFileFromHexString(const std::string& hexStr);
        
    private:
        //Main logic of parsing Portable Executables
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
        
        PE_BUFFER::Buffer* buffer{};
        
        static constexpr bool isBigEndian = (std::endian::native == std::endian::big); 
    };

};
#endif