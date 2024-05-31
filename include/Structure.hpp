#ifndef PE_STRUCTURE_HPP
#define PE_STRUCTURE_HPP

#include <Windows.h>
#include <stdint.h>
#include <winnt.h>

#include <boost/describe/class.hpp>

//Defines structure of Portable Executables
namespace PE_STRUCTURE {

	struct DosHeader { //DOS .EXE header

		WORD
			magic{}, //Magic number
			e_cblp{}, //Bytes on last page of file
			e_cp{}, //Pages in file
			e_crlc{}, //Relocations
			e_cparhdr{}, //Size of header in paragraphs
			e_minalloc{}, //Minimum extra paragraphs needed
			e_maxalloc{}, // Maximum extra paragraphs needed
			e_ss{}, //Initial (relative) SS value
			e_sp{}, //Initial SP value
			e_csum{}, //Checksum
			e_ip{}, //Initial IP value
			e_cs{}, //Initial (relative) CS value 
			e_lfarlc{}, //File address of relocation table
			e_ovno{}, //Overlay number
			e_res[4]{}, //Reserved words
			e_oemid{}, //OEM identifier
			e_oeminfo{}, //OEM information 
			e_res2[10]{}; //Reserved words

		DWORD e_lfanew{}; //Address for NT Headers
	};

    BOOST_DESCRIBE_STRUCT(DosHeader, (), (magic, e_cblp, e_cp, e_crlc, e_cparhdr,
        e_minalloc, e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno,
        e_res, e_oemid, e_oeminfo, e_res2, e_lfanew));

    
    struct ImageHeader{
        DWORD signature{}; //almost always PE/0/0
		IMAGE_FILE_HEADER FileHeader{}; //Some information, has OptionalHeader size
    };

    BOOST_DESCRIBE_STRUCT(ImageHeader, (), (signature, FileHeader));
};

//Structs that don't belong to namespace need to have describe outside of namespace

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

BOOST_DESCRIBE_STRUCT(IMAGE_IMPORT_DESCRIPTOR , (), (OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk));
BOOST_DESCRIBE_STRUCT(IMAGE_BOUND_IMPORT_DESCRIPTOR, (), (TimeDateStamp, OffsetModuleName, NumberOfModuleForwarderRefs));

BOOST_DESCRIBE_STRUCT(IMAGE_BASE_RELOCATION, (), (VirtualAddress, SizeOfBlock));

#endif