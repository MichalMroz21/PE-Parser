#ifndef PE_FILE
#define PE_FILE

#include "Structure.hpp"

class PEFile {
public:

    PEFile() = delete;

	PEFile(PE_STRUCTURE::DosHeader dosHeader, PE_STRUCTURE::ImageNtHeaders imageNTHeaders);
	PEFile(PE_STRUCTURE::DosHeader dosHeader, PE_STRUCTURE::ImageNtHeaders64 imageNTHeaders64);

private:
	bool is64Bit = false;

	PE_STRUCTURE::DosHeader dosHeader{};
	PE_STRUCTURE::ImageNtHeaders imageNTHeaders{};
	PE_STRUCTURE::ImageNtHeaders64 imageNTHeaders64{};

};

#endif