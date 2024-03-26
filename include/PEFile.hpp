#ifndef PE_FILE
#define PE_FILE

#include <Structure.hpp>
#include <stdexcept>
#include <boost/variant.hpp>

#include <iostream>

namespace PE_PARSER{
    class Parser;
};

namespace PE_DATA{

    using HeaderVariant = boost::variant<IMAGE_OPTIONAL_HEADER32*, IMAGE_OPTIONAL_HEADER64*>;

    class PEFile {
        friend class PE_PARSER::Parser;

    public:
        //DosHeader Data
        [[nodiscard]] WORD magicNumber();
        [[nodiscard]] WORD lastPageBytes();
        [[nodiscard]] WORD pagesInFile();
        [[nodiscard]] WORD relocations();
        [[nodiscard]] WORD sizeOfHeaderInParagraphs();
        [[nodiscard]] WORD minimumExtraParagraphs();
        [[nodiscard]] WORD maximumExtraParagraphs();
        [[nodiscard]] WORD initialSSValue();
        [[nodiscard]] WORD initialSPValue();
        [[nodiscard]] WORD checkSum();
        [[nodiscard]] WORD initialIPValue();
        [[nodiscard]] WORD initialCSValue();
        [[nodiscard]] WORD addressRelocationTable();
        [[nodiscard]] WORD overlayNumber();
        [[nodiscard]] WORD oemIdentifier();
        [[nodiscard]] WORD oemInformation();
        [[nodiscard]] DWORD headerAddress();

        //ImageHeader data
        [[nodiscard]] DWORD signature();
        [[nodiscard]] WORD machine();
        [[nodiscard]] WORD numberOfSections();
        [[nodiscard]] DWORD timeDateStamp();
        [[nodiscard]] DWORD pointerToSymbolTable();
        [[nodiscard]] DWORD numberOfSymbols();
        [[nodiscard]] WORD sizeOfOptionalHeader();
        [[nodiscard]] WORD charasteristics();

        //OptionalHeader data
        [[nodiscard]]

    protected:
        PEFile();

        void setTypeOfPE(WORD stateOfMachine);
        
        HeaderVariant getOptionalHeader();

        PE_STRUCTURE::DosHeader dosHeader{};
        PE_STRUCTURE::ImageHeader imageHeader{};

    private:
        //dev note: get them with getOptionalHeader
        IMAGE_OPTIONAL_HEADER32 imageOptionalHeader32{};
        IMAGE_OPTIONAL_HEADER64 imageOptionalHeader64{};

        bool is64Bit = false, wasTypeSet = false;
    };

}

#endif