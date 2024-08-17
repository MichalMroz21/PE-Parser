#ifndef PE_PARSER_HPP
#define PE_PARSER_HPP

#include <vector>
#include <windows.h>
#include <fstream>
#include <iostream>
#include <cstring>
#include <string>
#include <type_traits>
#include <windns.h>
#include <regex>
#include <utility>

#include <boost/mp11.hpp>
#include <boost/type_index.hpp>
#include <boost/describe.hpp>
#include <boost/endian/conversion.hpp>

#include "PEFile.hpp"
#include "Structure.hpp"
#include "Buffer.hpp"

#include "better_braces.hpp"

//Class for extracting bytes from Portable Executables
namespace PE_PARSER{

    class Parser {
    public:
        Parser();
        ~Parser();

        //User Entry Points into parsing Portable Executables
        [[nodiscard]] PE_DATA::PEFile* loadPEFileFromPath(const char* fullPEPath, bool freeBuffer = true);

        [[nodiscard]] PE_DATA::PEFile* loadPEFileFromBytes(const std::vector<BYTE>& bytes, bool freeBuffer = true);

        //hexString has to be of even size
        [[nodiscard]] PE_DATA::PEFile* loadPEFileFromHexString(const std::string& hexStr, bool freeBuffer = true);

        //Returns the buffer after parsing. If freeBuffer was set to true this will return nullptr.
        //If You want to get a buffer after parsing then set freeBuffer argument to false.
        //Remember to free the buffer Yourself after using it!
        [[nodiscard]] PE_BUFFER::Buffer* obtainBufferAndSetNull();

        //Extracts strings from PE (Buffer)
        //Where the key of the map is the offset of the string in PE, char is the type, and std::size_t is the length of string
        [[nodiscard]] std::map<std::uintptr_t, std::string> getStrings(PE_BUFFER::Buffer* buff);
        
    private:
        //Main logic of parsing Portable Executables
        PE_DATA::PEFile* loadPEFile(bool freeBuffer);

        //this function used outside of class may lead to memory leaks
        void freeBuffer();

        PE_BUFFER::Buffer* buffer{};

        static constexpr bool isBigEndian = (std::endian::native == std::endian::big);

        std::string getNullTerminatedString();

        //returns amount of bytes copied to struct
        template<typename Base, class Md = boost::describe::describe_members<Base, boost::describe::mod_any_access>>
        void copyBytesToStruct(Base& base, long long toCopy = sizeof(Base));

        template<typename Attr> 
        void copyBytesToStructInner(Attr& attr, long long toCopy);

        template<typename Arr> 
        void copyBytesToStructInnerArr(Arr& arr, long long toCopy);

        template<typename Attr> 
        void copyBytesToVariable(Attr& attr);

        template<typename Strct, typename Arr>
        void getStructsNullTerminated(Arr* arr, PE_DATA::PEFile* peFile);

        template<typename Strct, typename Arr>
        void getStructs(Arr* arr, PE_DATA::PEFile* peFile, std::size_t amount);

        template<typename T>
        void getVectorStructs(std::vector<T>* vector, PE_DATA::PEFile* peFile);

        void getBoundImportDirectoryData(PE_DATA::PEFile* peFile),
             getImportDirectoryData(PE_DATA::PEFile* peFile),
             getBaseRelocationDirectoryData(PE_DATA::PEFile* peFile),
             getDebugDirectoryData(PE_DATA::PEFile* peFile),
             getLoadConfigDirectoryData(PE_DATA::PEFile* peFile),
             getTLSDirectoryData(PE_DATA::PEFile* peFile),
             getExceptionDirectoryData(PE_DATA::PEFile* peFile),
             getSecurityDirectoryData(PE_DATA::PEFile *peFile),
             getExportDirectoryData(PE_DATA::PEFile *peFile);
    };
};
#endif