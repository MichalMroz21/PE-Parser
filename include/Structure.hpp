#ifndef PE_STRUCTURE_HPP
#define PE_STRUCTURE_HPP

#include <Windows.h>
#include <winnt.h>

#include <boost/describe/class.hpp>

//Defines structure of Portable Executables
namespace PE_STRUCTURE {
    struct ImageHeader{
        DWORD signature{}; //almost always PE/0/0
		IMAGE_FILE_HEADER FileHeader{}; //Some information, has OptionalHeader size
    };

    struct LoadConfigDirectory32_Rest{
        DWORD GuardCFCheckFunctionPointer{};
        DWORD GuardCFDispatchFunctionPointer{};
        DWORD GuardCFFunctionTable{};
        DWORD GuardCFFunctionCount{};
        DWORD GuardFlags{};
        DWORD CodeIntegrity[3];
        DWORD GuardAddressTakenIatEntryTable{};
        DWORD GuardAddressTakenIatEntryCount{};
        DWORD GuardLongJumpTargetTable{};
        DWORD GuardLongJumpTargetCount{};
    };

    struct LoadConfigDirectory64_Rest{
        ULONGLONG GuardCFCheckFunctionPointer{};
        ULONGLONG GuardCFDispatchFunctionPointer{};
        ULONGLONG GuardCFFunctionTable{};
        ULONGLONG GuardCFFunctionCount{};
        DWORD GuardFlags{};
        DWORD CodeIntegrity[3];
        ULONGLONG GuardAddressTakenIatEntryTable{};
        ULONGLONG GuardAddressTakenIatEntryCount{};
        ULONGLONG GuardLongJumpTargetTable{};
        ULONGLONG GuardLongJumpTargetCount{};
    };

    BOOST_DESCRIBE_STRUCT(ImageHeader, (), (signature, FileHeader));

    BOOST_DESCRIBE_STRUCT(LoadConfigDirectory32_Rest, (), (GuardCFCheckFunctionPointer, GuardCFDispatchFunctionPointer, GuardCFFunctionTable, GuardCFFunctionCount, GuardFlags, CodeIntegrity, GuardAddressTakenIatEntryTable, GuardAddressTakenIatEntryCount, GuardLongJumpTargetTable, GuardLongJumpTargetCount));
    BOOST_DESCRIBE_STRUCT(LoadConfigDirectory64_Rest, (), (GuardCFCheckFunctionPointer, GuardCFDispatchFunctionPointer, GuardCFFunctionTable, GuardCFFunctionCount, GuardFlags, CodeIntegrity, GuardAddressTakenIatEntryTable, GuardAddressTakenIatEntryCount, GuardLongJumpTargetTable, GuardLongJumpTargetCount));
};

BOOST_DESCRIBE_STRUCT(IMAGE_DOS_HEADER, (), (e_magic, e_cblp, e_cp, e_crlc, e_cparhdr,
        e_minalloc, e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno,
        e_res, e_oemid, e_oeminfo, e_res2, e_lfanew));

BOOST_DESCRIBE_STRUCT(IMAGE_FILE_HEADER, (), (Machine, NumberOfSections, TimeDateStamp,
        PointerToSymbolTable, NumberOfSymbols, SizeOfOptionalHeader, Characteristics));
        
BOOST_DESCRIBE_STRUCT(IMAGE_OPTIONAL_HEADER32, (), (Magic, MajorLinkerVersion, MinorLinkerVersion,
    SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode,
    BaseOfData, ImageBase, SectionAlignment, FileAlignment, MajorOperatingSystemVersion,
    MinorOperatingSystemVersion, MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion, Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum,
    Subsystem, DllCharacteristics, SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve,
    SizeOfHeapCommit, LoaderFlags, NumberOfRvaAndSizes, DataDirectory));

BOOST_DESCRIBE_STRUCT(IMAGE_OPTIONAL_HEADER64, (), (Magic, MajorLinkerVersion, MinorLinkerVersion,
    SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode,
    ImageBase, SectionAlignment, FileAlignment, MajorOperatingSystemVersion,
    MinorOperatingSystemVersion, MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion, Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum,
    Subsystem, DllCharacteristics, SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve,
    SizeOfHeapCommit, LoaderFlags, NumberOfRvaAndSizes, DataDirectory));

BOOST_DESCRIBE_STRUCT(IMAGE_DATA_DIRECTORY, (), (VirtualAddress, Size));

BOOST_DESCRIBE_STRUCT(IMAGE_SECTION_HEADER, (), (Name, Misc, VirtualAddress, SizeOfRawData,
    PointerToRawData, PointerToRelocations, PointerToLinenumbers, NumberOfRelocations,
    NumberOfLinenumbers, Characteristics));

BOOST_DESCRIBE_STRUCT(IMAGE_IMPORT_DESCRIPTOR, (), (OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk));
BOOST_DESCRIBE_STRUCT(IMAGE_BOUND_IMPORT_DESCRIPTOR, (), (TimeDateStamp, OffsetModuleName, NumberOfModuleForwarderRefs));

BOOST_DESCRIBE_STRUCT(IMAGE_BASE_RELOCATION, (), (VirtualAddress, SizeOfBlock));

BOOST_DESCRIBE_STRUCT(IMAGE_DEBUG_DIRECTORY, (), (Characteristics, TimeDateStamp, MajorVersion, MinorVersion, Type, SizeOfData, AddressOfRawData, PointerToRawData));

BOOST_DESCRIBE_STRUCT(IMAGE_LOAD_CONFIG_DIRECTORY32, (), (Size, TimeDateStamp, MajorVersion, MinorVersion, GlobalFlagsClear, GlobalFlagsSet, CriticalSectionDefaultTimeout, DeCommitFreeBlockThreshold, DeCommitTotalFreeThreshold, LockPrefixTable, MaximumAllocationSize, VirtualMemoryThreshold, ProcessHeapFlags, ProcessAffinityMask, CSDVersion, Reserved1, EditList, SecurityCookie, SEHandlerTable, SEHandlerCount));
BOOST_DESCRIBE_STRUCT(IMAGE_LOAD_CONFIG_DIRECTORY64, (), (Size, TimeDateStamp, MajorVersion, MinorVersion, GlobalFlagsClear, GlobalFlagsSet, CriticalSectionDefaultTimeout, DeCommitFreeBlockThreshold, DeCommitTotalFreeThreshold, LockPrefixTable, MaximumAllocationSize, VirtualMemoryThreshold, ProcessAffinityMask, ProcessHeapFlags, CSDVersion, Reserved1, EditList, SecurityCookie, SEHandlerTable, SEHandlerCount));

BOOST_DESCRIBE_STRUCT(IMAGE_TLS_DIRECTORY32, (), (StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex, AddressOfCallBacks, SizeOfZeroFill, Characteristics));
BOOST_DESCRIBE_STRUCT(IMAGE_TLS_DIRECTORY64, (), (StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex, AddressOfCallBacks, SizeOfZeroFill, Characteristics));

#endif