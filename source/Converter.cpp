#include <Converter.hpp>

namespace PE_CONVERTER{

    Converter::Converter(){}

    std::string Converter::getMachineStr(WORD machine){
        switch (machine){

            case IMAGE_FILE_MACHINE_UNKNOWN:
                return "unknown";                                       
            case IMAGE_FILE_MACHINE_I386:
                return "intel 386";               
            case IMAGE_FILE_MACHINE_R3000:
                return "MIPS little-endian";               
            case IMAGE_FILE_MACHINE_R4000:
                return "MIPS little-endian";               
            case IMAGE_FILE_MACHINE_R10000:
                return "MIPS little-endian";              
            case IMAGE_FILE_MACHINE_WCEMIPSV2:
                return "MIPS little-endian WCE v2";         
            case IMAGE_FILE_MACHINE_ALPHA:
                return "Alpha_AXP";              
            case IMAGE_FILE_MACHINE_SH3:
                return "SH3 little-endian";                
            case IMAGE_FILE_MACHINE_SH3DSP:
                return "SH3DSP little-endian";            
            case IMAGE_FILE_MACHINE_SH3E:
                return "SH3E little-endian";                
            case IMAGE_FILE_MACHINE_SH4:
                return "SH4 little-endian";                 
            case IMAGE_FILE_MACHINE_SH5:
                return "SH5 little-endian";                 
            case IMAGE_FILE_MACHINE_ARM:
                return "ARM little-endian";                
            case IMAGE_FILE_MACHINE_THUMB:
                return "ARM Thumb/Thumb-2 little-endian";               
            case IMAGE_FILE_MACHINE_ARMNT:
                return "ARM Thumb-2 little-endian";               
            case IMAGE_FILE_MACHINE_AM33:
                return "AM33";              
            case IMAGE_FILE_MACHINE_POWERPC:
                return "IBM PowerPC little-endian";             
            case IMAGE_FILE_MACHINE_POWERPCFP:
                return "IBM PowerPCFP";         
            case IMAGE_FILE_MACHINE_IA64:
                return "Intel 64";                
            case IMAGE_FILE_MACHINE_MIPS16:
                return "MIPS";              
            case IMAGE_FILE_MACHINE_ALPHA64:
                return "ALPHA64";             
            case IMAGE_FILE_MACHINE_MIPSFPU:
                return "MIPSFPU";             
            case IMAGE_FILE_MACHINE_MIPSFPU16:
                return "MIPSFPU16";                       
            case IMAGE_FILE_MACHINE_TRICORE:
                return "TRICORE Infineon";             
            case IMAGE_FILE_MACHINE_CEF:
                return "CEF";               
            case IMAGE_FILE_MACHINE_EBC:
                return "EFI Byte Code";                 
            case IMAGE_FILE_MACHINE_AMD64:
                return "AMD64 (K8)";               
            case IMAGE_FILE_MACHINE_M32R:
                return "M32R little-endian";                
            case IMAGE_FILE_MACHINE_ARM64:
                return "ARM64 little-endian";               
            case IMAGE_FILE_MACHINE_CEE:
                return "CEE";               
            default:
                return "invalid bytes";
        }   
    }

    std::string Converter::getTimestampStr(DWORD timestamp){
        std::stringstream str;
        boost::posix_time::time_facet *facet = new boost::posix_time::time_facet("%d.%m.%Y-%H:%M:%S-UTC");
        str.imbue(std::locale(str.getloc(), facet));
        str << boost::posix_time::second_clock::universal_time();
        return str.str();
    } 

    std::vector<std::string> Converter::getCharasteristics(WORD charasteristics){

        std::vector<std::string> description{};

        std::vector<std::string> descMap{
            {"Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files."},
            {"Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error."},
            {"COFF line numbers have been removed. This flag is deprecated and should be zero."},
            {"COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero."},
            {"Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero."},
            {"Application can handle > 2-GB addresses."},
            {"This flag is reserved for future use."},
            {"Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero."},
            {"Machine is based on a 32-bit-word architecture."},
            {"Debugging information is removed from the image file."},
            {"If the image is on removable media, fully load it and copy it to the swap file."},
            {"If the image is on network media, fully load it and copy it to the swap file."},
            {"The image file is a system file, not a user program."},
            {"The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run."},
            {"The file should be run only on a uniprocessor machine."},
            {"Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero."}
        };

        boost::dynamic_bitset<> bits(sizeof(charasteristics), charasteristics);

        boost::copy_if(descMap, std::back_inserter(description), [&](int value) {
            return bits[description.size()];
        });

        return description;
    } 
};