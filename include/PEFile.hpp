#ifndef PE_FILE
#define PE_FILE

#include "Structure.hpp"

namespace PE_DATA{

    class PEFile {
    public:

        PEFile();

        PEFile(PE_STRUCTURE::DosHeader dosHeader, PE_STRUCTURE::ImageNtHeaders imageNTHeaders);
        PEFile(PE_STRUCTURE::DosHeader dosHeader, PE_STRUCTURE::ImageNtHeaders64 imageNTHeaders64);

        PE_STRUCTURE::DosHeader dosHeader{};
        PE_STRUCTURE::ImageNtHeaders imageNTHeaders{};
        PE_STRUCTURE::ImageNtHeaders64 imageNTHeaders64{};

    private:
        bool is64Bit = false;
    };


}

#endif