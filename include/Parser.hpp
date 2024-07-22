#ifndef PE_PARSER_HPP
#define PE_PARSER_HPP

#include <vector>
#include <windows.h>
#include <fstream>
#include <iostream>
#include <cstring>
#include <string>
#include <type_traits>
#include <winDNS.h>

#include <boost/mp11.hpp>
#include <boost/type_index.hpp>
#include <boost/describe.hpp>
#include <boost/endian/conversion.hpp>

#include <PEFile.hpp>
#include <Structure.hpp>
#include <Buffer.hpp>

#include <better_braces.hpp>

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
        PE_DATA::PEFile* loadPEFileFromBytes(const std::vector<BYTE>& bytes);

        //hexString has to be of even size
        [[nodiscard]]
        PE_DATA::PEFile* loadPEFileFromHexString(const std::string& hexStr);
        
    private:
        //Main logic of parsing Portable Executables
        PE_DATA::PEFile* loadPEFile();

        void freeBuffer();
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
        
        PE_BUFFER::Buffer* buffer{};
        
        static constexpr bool isBigEndian = (std::endian::native == std::endian::big);

        void getBoundImportDirectoryData(PE_DATA::PEFile* peFile),
             getImportDirectoryData(PE_DATA::PEFile* peFile),
             getBaseRelocationDirectoryData(PE_DATA::PEFile* pFile),
             getDebugDirectoryData(PE_DATA::PEFile* peFile),
             getLoadConfigDirectoryData(PE_DATA::PEFile* pFile),
             getTLSDirectoryData(PE_DATA::PEFile* peFile),
             getExceptionDirectoryData(PE_DATA::PEFile* peFile);

        void getSecurityDirectoryData(PE_DATA::PEFile *peFile);

        void getExportDirectoryData(PE_DATA::PEFile *peFile);
    };
};
#endif