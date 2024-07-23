#include <Converter.hpp>

namespace PE_CONVERTER{

    Converter::Converter(){}

    std::string Converter::getMagicValue(WORD magic){
        switch(magic){
            case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                return "PE32";
            case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                return "PE32+";
            case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
                return "ROM";
            default:
                throw std::invalid_argument("Magic Value is invalid");
        }
    }

    std::string Converter::getSubsystem(WORD subsystem){
        std::unordered_map<WORD, std::string> subsystemMap{
            {IMAGE_FILE_MACHINE_UNKNOWN, "unknown"}, {IMAGE_SUBSYSTEM_NATIVE, "Device drivers and native Windows processes"},
            {IMAGE_SUBSYSTEM_WINDOWS_GUI, "The Windows graphical user interface (GUI) subsystem"}, 
            {IMAGE_SUBSYSTEM_WINDOWS_CUI, "The Windows character subsystem"},
            {IMAGE_SUBSYSTEM_OS2_CUI, "The OS/2 character subsystem"}, {IMAGE_SUBSYSTEM_POSIX_CUI, "The Posix character subsystem"},
            {IMAGE_SUBSYSTEM_NATIVE_WINDOWS, "Native Win9x driver"}, {IMAGE_SUBSYSTEM_WINDOWS_CE_GUI, "Windows CE"},
            {IMAGE_SUBSYSTEM_EFI_APPLICATION, "An Extensible Firmware Interface (EFI) application"}, 
            {IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER, "An EFI driver with boot services"},
            {IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER, "An EFI driver with run-time services"}, {IMAGE_SUBSYSTEM_EFI_ROM, "An EFI ROM image"},
            {IMAGE_SUBSYSTEM_XBOX, "XBOX"}, {IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION, "Windows boot application."}
        };

        std::string subsystemStr = subsystemMap[subsystem];

        if(subsystemStr.empty()) 
            throw std::invalid_argument("Invalid Subsystem Word");

        return subsystemStr;
    }

    std::string Converter::getMachineStr(WORD machine){
        std::unordered_map<WORD, std::string> machineMap{
            {IMAGE_FILE_MACHINE_UNKNOWN, "unknown"}, {IMAGE_FILE_MACHINE_I386, "intel 386"},
            {IMAGE_FILE_MACHINE_R3000, "MIPS little-endian"}, {IMAGE_FILE_MACHINE_R4000, "MIPS little-endian"},
            {IMAGE_FILE_MACHINE_R10000, "MIPS little-endian"}, {IMAGE_FILE_MACHINE_WCEMIPSV2, "MIPS little-endian WCE v2"},
            {IMAGE_FILE_MACHINE_ALPHA, "Alpha_AXP"}, {IMAGE_FILE_MACHINE_SH3, "SH3 little-endian"},
            {IMAGE_FILE_MACHINE_SH3DSP, "SH3DSP little-endian"}, {IMAGE_FILE_MACHINE_SH3E, "SH3E little-endian"},
            {IMAGE_FILE_MACHINE_SH4, "SH4 little-endian"}, {IMAGE_FILE_MACHINE_SH5, "SH5 little-endian"},
            {IMAGE_FILE_MACHINE_ARM, "ARM little-endian"}, {IMAGE_FILE_MACHINE_THUMB, "ARM Thumb/Thumb-2 little-endian"},
            {IMAGE_FILE_MACHINE_ARMNT, "ARM Thumb-2 little-endian"}, {IMAGE_FILE_MACHINE_AM33, "AM33"},
            {IMAGE_FILE_MACHINE_POWERPC, "IBM PowerPC little-endian"}, {IMAGE_FILE_MACHINE_POWERPCFP, "IBM PowerPCFP"},
            {IMAGE_FILE_MACHINE_IA64, "Intel 64"}, {IMAGE_FILE_MACHINE_MIPS16, "MIPS"},
            {IMAGE_FILE_MACHINE_ALPHA64, "ALPHA64"}, {IMAGE_FILE_MACHINE_MIPSFPU, "MIPSFPU"},
            {IMAGE_FILE_MACHINE_MIPSFPU16, "MIPSFPU16"}, {IMAGE_FILE_MACHINE_TRICORE, "TRICORE Infineon"},
            {IMAGE_FILE_MACHINE_CEF, "CEF"}, {IMAGE_FILE_MACHINE_EBC, "EFI Byte Code"},
            {IMAGE_FILE_MACHINE_AMD64, "AMD64 (K8)"}, {IMAGE_FILE_MACHINE_M32R, "M32R little-endian"},
            {IMAGE_FILE_MACHINE_ARM64, "ARM64 little-endian"}, {IMAGE_FILE_MACHINE_CEE, "CEE"}
        };

        std::string machineStr = machineMap[machine];

        if(machineStr.empty()) 
            throw std::invalid_argument("Invalid Machine Word");

        return machineStr;
    }

    std::string Converter::getTimestampStr(DWORD timestamp){
        std::stringstream str;
        boost::posix_time::time_facet *facet = new boost::posix_time::time_facet("%d.%m.%Y-%H:%M:%S-UTC");
        str.imbue(std::locale(str.getloc(), facet));
        str << boost::posix_time::from_time_t(timestamp);
        return str.str();
    }

    std::vector<std::string> Converter::getDllCharacteristics(WORD dllCharasteristics){

        std::vector<std::string> description{},
                                 reservedVec{},
                                 descMap
        {
            {"Image can handle a high entropy 64-bit virtual address space."},
            {"DLL can be relocated at load time."},
            {"Code Integrity checks are enforced."},
            {"Image is NX compatible."},
            {"Isolation aware, but do not isolate the image."},
            {"Does not use structured exception (SE) handling. No SE handler may be called in this image."},
            {"Do not bind the image."},
            {"Image must execute in an AppContainer."},
            {"A WDM driver."},
            {"Image supports Control Flow Guard."},
            {"Terminal Server aware."},
        };

        constexpr std::size_t RESERVED_BITS_CNT = 5;

        for(int i = 0; i < RESERVED_BITS_CNT; i++) 
            reservedVec.push_back(std::string("Reserved, must be zero"));

        descMap.insert(descMap.begin(), reservedVec.begin(), reservedVec.end());

        boost::dynamic_bitset<> bits(sizeof(dllCharasteristics) * CHAR_BIT, dllCharasteristics);

        if(bits.size() > descMap.size()) 
            throw std::logic_error("Size of Bits higher than descMap");

        for(std::size_t i = 0; i < bits.size(); i++){
            if(bits[i]) 
                description.push_back(descMap[i]);
        }

        return description;
    } 

    std::vector<std::string> Converter::getCharacteristics(WORD charasteristics){

        std::vector<std::string> description{};

        std::vector<std::string> descMap{
            {"Image only, Windows CE, and Microsoft Windows NT and later."},
            {"Image only. The image file is valid and can be run."},
            {"COFF line numbers have been removed."},
            {"COFF symbol table entries for local symbols have been removed."},
            {"Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero."},
            {"Application can handle > 2-GB addresses."},
            {"This flag is reserved for future use."},
            {"Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory."},
            {"Machine is based on a 32-bit-word architecture."},
            {"Debugging information is removed from the image file."},
            {"If the image is on removable media, fully load it and copy it to the swap file."},
            {"If the image is on network media, fully load it and copy it to the swap file."},
            {"The image file is a system file, not a user program."},
            {"The image file is a dynamic-link library (DLL)."},
            {"The file should be run only on a uniprocessor machine."},
            {"Big endian: the MSB precedes the LSB in memory."}
        };

        boost::dynamic_bitset<> bits(sizeof(charasteristics) * CHAR_BIT, charasteristics);

        if(bits.size() > descMap.size()) 
            throw std::logic_error("Size of Bits higher than descMap");

        for(std::size_t i = 0; i < bits.size(); i++){
            if(bits[i]) 
                description.push_back(descMap[i]);
        }

        return description;
    } 
};