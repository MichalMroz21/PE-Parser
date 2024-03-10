#ifndef STRUCTURE_H
#define STRUCTURE_H

#include <Windows.h>
#include <stdint.h>
#include <winnt.h>

#include <boost/describe/class.hpp>

namespace PE_STRUCTURE {

	struct DosHeader {

		WORD
			magic{}, //DOS .EXE header
			e_cblp{}, //Magic number
			e_cp{}, //Bytes on last page of file
			e_crlc{}, //Pages in file
			e_cparhdr{}, //Relocations
			e_minalloc{}, //Size of header in paragraphs
			e_maxalloc{}, //Minimum extra paragraphs needed
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

	//For PE32+ (64-bit) Executables
	struct ImageNtHeaders64 {

		DWORD signature{}; //almost always PE/0/0
		IMAGE_FILE_HEADER FileHeader{}; //Some information, has OptionalHeader size
		IMAGE_OPTIONAL_HEADER64 OptionalHeader{}; //Some important info
	};

    BOOST_DESCRIBE_STRUCT(ImageNtHeaders64, (), (signature, FileHeader, OptionalHeader));

	//For PE32 Executables
	struct ImageNtHeaders {

		DWORD signature{};
		IMAGE_FILE_HEADER FileHeader{};
		IMAGE_OPTIONAL_HEADER32 OptionalHeader{};
	};

    BOOST_DESCRIBE_STRUCT(ImageNtHeaders, (), (signature, FileHeader, OptionalHeader));
};

#endif