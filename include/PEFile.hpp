#ifndef PE_FILE
#define PE_FILE

#include <Structure.hpp>
#include <stdexcept>

#include <boost/variant.hpp>
#include <boost/mp11.hpp>

#include <iostream>
#include <cstdint>

namespace PE_PARSER{
    class Parser;
};

namespace PE_DATA{

    using Header32 = IMAGE_OPTIONAL_HEADER32;
    using Header64 = IMAGE_OPTIONAL_HEADER64;

    using HeaderVariant = boost::variant<Header32*, Header64*>;

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
        [[nodiscard]] WORD magic();
        [[nodiscard]] BYTE majorLinkerVersion();
        [[nodiscard]] BYTE minorLinkerVersion();
        [[nodiscard]] DWORD sizeOfCode();
        [[nodiscard]] DWORD sizeOfInitializedData();
        [[nodiscard]] DWORD sizeOfUninitializedData();
        [[nodiscard]] DWORD addressOfEntryPoint();
        [[nodiscard]] DWORD baseOfCode();
        [[nodiscard]] DWORD baseOfData();
        [[nodiscard]] ULONGLONG imageBase();
        [[nodiscard]] DWORD sectionAlignment();
        [[nodiscard]] DWORD fileAlignment();
        [[nodiscard]] WORD majorOperatingSystemVersion();
        [[nodiscard]] WORD minorOperatingSystemVersion();
        [[nodiscard]] WORD majorImageVersion();
        [[nodiscard]] WORD minorImageVersion();
        [[nodiscard]] WORD majorSubsystemVersion();
        [[nodiscard]] WORD minorSubsystemVersion();
        [[nodiscard]] DWORD win32VersionValue();
        [[nodiscard]] DWORD sizeOfImage();
        [[nodiscard]] DWORD sizeOfHeaders();
        [[nodiscard]] DWORD checkSumOptional();
        [[nodiscard]] WORD subsystem();
        [[nodiscard]] WORD dllCharasteristics();
        [[nodiscard]] ULONGLONG sizeOfStackReserve();
        [[nodiscard]] ULONGLONG sizeOfStackCommit();
        [[nodiscard]] ULONGLONG sizeOfHeapReserve();
        [[nodiscard]] ULONGLONG sizeOfHeapCommit();
        [[nodiscard]] DWORD loaderFlags();
        [[nodiscard]] DWORD numberOfRvaAndSizes();

        [[nodiscard]] HeaderVariant getOptionalHeader();

        [[nodiscard]] PE_STRUCTURE::DosHeader getDosHeaderStruct();
        [[nodiscard]] PE_STRUCTURE::ImageHeader getImageHeaderStruct();

    protected:
        PEFile();

        void setTypeOfPE(WORD stateOfMachine);

        ULONGLONG getOptHeaderAttr(OptHeaderAttr attr, int attrSize)

        bool is64Bit();
        
        PE_STRUCTURE::DosHeader dosHeader{};
        PE_STRUCTURE::ImageHeader imageHeader{};

        enum class OptHeaderAttr{
            magic, majorLinkerVersion, minorLinkerVersion,
            sizeOfCode, sizeOfInitializedData, sizeOfUninitializedData,
            addressOfEntryPoint, baseOfCode, baseOfData,
            imageBase, sectionAlignment, fileAlignment,
            majorOperatingSystemVersion, minorOperatingSystemVersion,
            majorImageVersion, minorImageVersion, majorSubsystemVersion,
            minorSubsystemVersion, win32VersionValue, sizeOfImage,
            sizeOfHeaders, checkSum, subsystem, dllCharasteristics,
            sizeOfStackReserve, sizeOfStackCommit, sizeOfHeapReserve,
            sizeOfHeapCommit, loaderFlags, numberOfRvaAndSizes
        };

    private:
        //dev note: get them with getOptionalHeader
        IMAGE_OPTIONAL_HEADER32 imageOptionalHeader32{};
        IMAGE_OPTIONAL_HEADER64 imageOptionalHeader64{};

        bool is64Bit = false, wasTypeSet = false;
    };

}

#endif