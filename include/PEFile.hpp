#ifndef PE_FILE_HPP
#define PE_FILE_HPP

#include <Structure.hpp>
#include <Converter.hpp>

#include <boost/variant.hpp>
#include <boost/mp11.hpp>
#include <boost/type_index.hpp>
#include <boost/describe.hpp>

#include <cstdint>
#include <stdexcept>
#include <iostream>
#include <type_traits>

namespace PE_PARSER{
    class Parser;
};

//Class to read data from Parsed Portable Executable
namespace PE_DATA{

    using Header32 = IMAGE_OPTIONAL_HEADER32;
    using Header64 = IMAGE_OPTIONAL_HEADER64;

    using HeaderVariant = boost::variant<Header32*, Header64*>;
    using ConfigVariant = boost::variant<IMAGE_LOAD_CONFIG_DIRECTORY32*, IMAGE_LOAD_CONFIG_DIRECTORY64*>;
    using ConfigRestVariant = boost::variant<PE_STRUCTURE::LoadConfigDirectory32_Rest*, PE_STRUCTURE::LoadConfigDirectory64_Rest*>;
    using TLSVariant = boost::variant<IMAGE_TLS_DIRECTORY32*, IMAGE_TLS_DIRECTORY64*>;

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
        [[nodiscard]] IMAGE_DATA_DIRECTORY* dataDirectory();

        //LoadConfig data
        [[nodiscard]] DWORD LoadConfigSize();
        [[nodiscard]] DWORD LoadConfigTimeDateStamp();
        [[nodiscard]] WORD LoadConfigMajorVersion();
        [[nodiscard]] WORD LoadConfigMinorVersion();
        [[nodiscard]] DWORD LoadConfigGlobalFlagsClear();
        [[nodiscard]] DWORD LoadConfigGlobalFlagsSet();
        [[nodiscard]] DWORD LoadConfigCriticalSectionDefaultTimeout();
        [[nodiscard]] ULONGLONG LoadConfigDeCommitFreeBlockThreshold();
        [[nodiscard]] ULONGLONG LoadConfigDeCommitTotalFreeThreshold();
        [[nodiscard]] ULONGLONG LoadConfigLockPrefixTable();
        [[nodiscard]] ULONGLONG LoadConfigMaximumAllocationSize();
        [[nodiscard]] ULONGLONG LoadConfigVirtualMemoryThreshold();
        [[nodiscard]] ULONGLONG LoadConfigProcessAffinityMask();
        [[nodiscard]] DWORD LoadConfigProcessHeapFlags();
        [[nodiscard]] WORD LoadConfigCSDVersion();
        [[nodiscard]] WORD LoadConfigDependentLoadFlags();
        [[nodiscard]] ULONGLONG LoadConfigEditList();
        [[nodiscard]] ULONGLONG LoadConfigSecurityCookie();
        [[nodiscard]] ULONGLONG LoadConfigSEHandlerTable();
        [[nodiscard]] ULONGLONG LoadConfigSEHandlerCount();
        [[nodiscard]] ULONGLONG LoadConfigGuardCFCheckFunctionPointer();
        [[nodiscard]] ULONGLONG LoadConfigGuardCFDispatchFunctionPointer();
        [[nodiscard]] ULONGLONG LoadConfigGuardCFFunctionTable();
        [[nodiscard]] ULONGLONG LoadConfigGuardCFFunctionCount();
        [[nodiscard]] DWORD LoadConfigGuardFlags();
        [[nodiscard]] DWORD* LoadConfigCodeIntegrity();
        [[nodiscard]] ULONGLONG LoadConfigGuardAddressTakenIatEntryTable();
        [[nodiscard]] ULONGLONG LoadConfigGuardAddressTakenIatEntryCount();
        [[nodiscard]] ULONGLONG LoadConfigGuardLongJumpTargetTable();
        [[nodiscard]] ULONGLONG LoadConfigGuardLongJumpTargetCount();

        //Data Directory (in optional header) data
        //Returns address and size of data directory
        [[nodiscard]] std::pair<DWORD, std::size_t> exportDirectory();
        [[nodiscard]] std::pair<DWORD, std::size_t> importDirectory();
        [[nodiscard]] std::pair<DWORD, std::size_t> resourceDirectory();
        [[nodiscard]] std::pair<DWORD, std::size_t> exceptionDirectory();
        [[nodiscard]] std::pair<DWORD, std::size_t> securityDirectory();
        [[nodiscard]] std::pair<DWORD, std::size_t> baseRelocationDirectory();
        [[nodiscard]] std::pair<DWORD, std::size_t> debugDirectory();
        [[nodiscard]] std::pair<DWORD, std::size_t> architectureDirectory();
        [[nodiscard]] std::pair<DWORD, std::size_t> globalPtrDirectory();
        [[nodiscard]] std::pair<DWORD, std::size_t> tlsDirectory();
        [[nodiscard]] std::pair<DWORD, std::size_t> loadConfigDirectory();
        [[nodiscard]] std::pair<DWORD, std::size_t> boundImportDirectory();
        [[nodiscard]] std::pair<DWORD, std::size_t> iatDirectory();
        [[nodiscard]] std::pair<DWORD, std::size_t> delayImportDescriptor();
        [[nodiscard]] std::pair<DWORD, std::size_t> clrRuntimeHeader();

        //TLS Directory data
        [[nodiscard]] ULONGLONG tlsStartAddressOfRawData();
        [[nodiscard]] ULONGLONG tlsEndAddressOfRawData();
        [[nodiscard]] ULONGLONG tlsAddressOfIndex();
        [[nodiscard]] ULONGLONG tlsAddressOfCallBacks();
        [[nodiscard]] ULONGLONG tlsSizeOfZeroFill();
        [[nodiscard]] ULONGLONG tlsCharacteristics();

        //Section Headers data
        [[nodiscard]] std::vector<IMAGE_SECTION_HEADER>* getSectionHeaders(bool getEmpty = false);

        //Data Directories
        [[nodiscard]] std::vector<IMAGE_IMPORT_DESCRIPTOR>* getImportDirectoryTable(bool getEmpty = false);
        [[nodiscard]] std::vector<std::vector<std::pair<std::optional<WORD>, std::unique_ptr<IMAGE_IMPORT_BY_NAME>>>>* getImportByNameTable(bool getEmpty = false);
        [[nodiscard]] std::vector<IMAGE_BOUND_IMPORT_DESCRIPTOR>* getBoundImportDirectoryTable(bool getEmpty = false);
        [[nodiscard]] std::vector<std::string>* getImportDirectoryNames(bool getEmpty = false);
        [[nodiscard]] std::vector<std::string>* getBoundImportDirectoryNames(bool getEmpty = false);
        [[nodiscard]] std::vector<std::pair<IMAGE_BASE_RELOCATION, std::vector<WORD>>>* getBaseRelocationTable(bool getEmpty = false);
        [[nodiscard]] std::vector<IMAGE_DEBUG_DIRECTORY>* getDebugDirectoryTable(bool getEmpty = false);

        [[nodiscard]] HeaderVariant getOptionalHeader(bool getEmpty = false);
        [[nodiscard]] ConfigVariant getLoadConfigDirectory(bool getEmpty = false);
        [[nodiscard]] ConfigRestVariant getLoadConfigDirectoryRest(bool getEmpty = false);
        [[nodiscard]] TLSVariant getTLSDirectory(bool getEmpty = false);

        [[nodiscard]] IMAGE_DOS_HEADER* getDosHeader(bool getEmpty = false);
        [[nodiscard]] PE_STRUCTURE::ImageHeader* getImageHeader(bool getEmpty = false);

        [[nodiscard]] std::uintptr_t translateRVAtoRaw(std::uintptr_t rva);

    protected:
        PEFile();

        bool getIs64Bit();

        IMAGE_DOS_HEADER dosHeader{};
        PE_STRUCTURE::ImageHeader imageHeader{};

        void setTypeOfPE(WORD stateOfMachine);

        enum class OptHeaderAttr{
            magic = 0, majorLinkerVersion, minorLinkerVersion,
            sizeOfCode, sizeOfInitializedData, sizeOfUninitializedData,
            addressOfEntryPoint, baseOfCode, baseOfData,
            imageBase, sectionAlignment, fileAlignment,
            majorOperatingSystemVersion, minorOperatingSystemVersion,
            majorImageVersion, minorImageVersion, majorSubsystemVersion,
            minorSubsystemVersion, win32VersionValue, sizeOfImage,
            sizeOfHeaders, checkSum, subsystem, dllCharasteristics,
            sizeOfStackReserve, sizeOfStackCommit, sizeOfHeapReserve,
            sizeOfHeapCommit, loaderFlags, numberOfRvaAndSizes, dataDirectory
        };

        enum class DataDirectory{
            exportDirectory = 0, importDirectory, resourceDirectory,
            exceptionDirectory, securityDirectory, baseRelocationDirectory,
            debugDirectory, architectureDirectory, globalPtrDirectory,
            tlsDirectory, loadConfigDirectory, boundImportDirectory,
            iatDirectory, delayImportDescriptor, clrRuntimeHeader
        };

        enum class LoadConfigData{
            Size = 0, TimeDateStamp, MajorVersion, MinorVersion,
            GlobalFlagsClear, GlobalFlagsSet, CriticalSectionDefaultTimeout,
            DeCommitFreeBlockThreshold, DeCommitTotalFreeThreshold,
            LockPrefixTable, MaximumAllocationSize, VirtualMemoryThreshold,
            ProcessAffinityMask, ProcessHeapFlags, CSDVersion,
            DependentLoadFlags, EditList, SecurityCookie, SEHandlerTable,
            SEHandlerCount, GuardCFCheckFunctionPointer, GuardCFDispatchFunctionPointer,
            GuardCFFunctionTable, GuardCFFunctionCount, GuardFlags,
            CodeIntegrity, GuardAddressTakenIatEntryTable, GuardAddressTakenIatEntryCount,
            GuardLongJumpTargetTable, GuardLongJumpTargetCount
        };

        enum class TLSData{
            StartAddressOfRawData = 0, EndAddressOfRawData, AddressOfIndex,
            AddressOfCallBacks, SizeOfZeroFill, Characteristics
        };

        std::pair<DWORD, std::size_t> getDataDirectoryPairEnum(DataDirectory dir);

        template<typename AttrType>
        AttrType getOptHeaderAttr(OptHeaderAttr attr);

        template<typename AttrType>
        AttrType getTLSData(TLSData tlsData);

        template<typename T>
        bool isTypeSet(T *type){
            T zeroStruct{};
            return memcmp(type, &zeroStruct, sizeof(T)) != 0;
        }

        void allocateSectionHeaders(std::size_t numberOfSections);

        std::uintptr_t getRawDirectoryAddress(DataDirectory dir);

    private:
        //dev note: get them with getOptionalHeader
        Header32 imageOptionalHeader32{};
        Header64 imageOptionalHeader64{};

        IMAGE_LOAD_CONFIG_DIRECTORY32 loadConfigDirectory32{};
        IMAGE_LOAD_CONFIG_DIRECTORY64 loadConfigDirectory64{};

        IMAGE_TLS_DIRECTORY32 tlsDirectory32{};
        IMAGE_TLS_DIRECTORY64 tlsDirectory64{};

        PE_STRUCTURE::LoadConfigDirectory32_Rest loadConfigDirectoryRest32{};
        PE_STRUCTURE::LoadConfigDirectory64_Rest loadConfigDirectoryRest64{};

        template<typename AttrType>
        AttrType getLoadConfigData(LoadConfigData confData);

        std::vector<IMAGE_SECTION_HEADER> imageSectionHeaders{};
        std::vector<IMAGE_IMPORT_DESCRIPTOR> importDirectoryTable{};
        std::vector<std::string> importDirectoryNames{};
        std::vector<std::vector<std::pair<std::optional<WORD>, std::unique_ptr<IMAGE_IMPORT_BY_NAME>>>> importByNameTable{};
        std::vector<IMAGE_DEBUG_DIRECTORY> debugDirectoryTable{};

        std::vector<IMAGE_BOUND_IMPORT_DESCRIPTOR> boundImportDirectoryTable{};
        std::vector<std::string> boundImportDirectoryNames{};

        std::vector<std::pair<IMAGE_BASE_RELOCATION, std::vector<WORD>>> baseRelocationDirectoryTable{};

        bool is64Bit = false, wasTypeSet = false;
    };

}
#endif