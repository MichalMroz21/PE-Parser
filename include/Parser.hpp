#ifndef PARSER
#define PARSER

#include <vector>
#include <stdint.h>
#include <windows.h>
#include <fstream>
#include <iostream>
#include <cstring>
#include <type_traits>

#include <boost/mp11.hpp>
#include <boost/type_index.hpp>
#include <boost/describe.hpp>

#include "PEFile.hpp"
#include "Structure.hpp"
#include "Buffer.hpp"

namespace PE_PARSER{

    class Parser {
    public:

        Parser();
        ~Parser();

        [[nodiscard]]
        PE_DATA::PEFile* loadPEFileFromPath(const char* fullPEPath);

        [[nodiscard]]
        PE_DATA::PEFile* loadPEFileFromBinary(PE_BUFFER::Buffer* PEBinary);
        
    private:

        //returns amount of bytes copied to struct
        template<typename Base, class Md = boost::describe::describe_members<Base, boost::describe::mod_any_access>>
        void copyBytesToStruct(Base& base);

        template<typename Attr> 
        void copyBytesToStructInner(Attr& attr);

        void setInitBuffer(const std::vector<BYTE>& PEBinary);

        bool isBigEndianCheck(void);

        bool isBigEndian{};
        PE_BUFFER::Buffer* buffer{};
        int bufferBeginPtr{};
    };

};
#endif