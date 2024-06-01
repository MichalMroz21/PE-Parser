#include <PEFile.hpp>

namespace PE_DATA{
    PEFile::PEFile(){
        this->imageHeader.FileHeader.SizeOfOptionalHeader = 0;
    }

    void PEFile::setTypeOfPE(WORD stateOfMachine){
        switch(stateOfMachine){
            case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                this->is64Bit = false;
                break;
            case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                this->is64Bit = true;
                break;
            default:
                throw std::invalid_argument("Invalid or unsupported stateOfMachine!");
        }
        this->wasTypeSet = true;
    }

    bool PEFile::getIs64Bit(){
        if(!this->wasTypeSet){
            throw std::logic_error("Type of PE was not set before calling this method!");
        }
        return this->is64Bit;
    }

    template<typename AttrType>
    AttrType PEFile::getOptHeaderAttr(OptHeaderAttr attrEnum){

        return boost::apply_visitor([&attrEnum, this](auto x) -> AttrType {

            if constexpr (std::is_same_v<decltype(*x), Header32&> || std::is_same_v<decltype(*x), Header64&>){

                std::uintptr_t attrPtr{}, structPtr = reinterpret_cast<std::uintptr_t>(x);

                int attrCnt{};

                if constexpr (std::is_same_v<decltype(*x), Header64&>){

                    if(attrEnum == OptHeaderAttr::baseOfData){
                        throw std::logic_error("Trying to obtain attribute of base of data on x64 PE");
                    }

                    if(attrEnum > OptHeaderAttr::baseOfData){
                        attrEnum = static_cast<OptHeaderAttr>(static_cast<int>(attrEnum) - 1);
                    }
                }

                boost::mp11::mp_for_each<boost::describe::describe_members<std::remove_reference_t<decltype(*x)>, boost::describe::mod_any_access>>
                ([&](auto attr){
                    if(static_cast<int>(attrEnum) == attrCnt){
                        attrPtr = reinterpret_cast<std::uintptr_t>(&( x->*(attr.pointer) ));
                    }
                    attrCnt++;
                });

                if(attrPtr == 0) throw std::invalid_argument("Invalid enum argument");

                if( (attrPtr + sizeof(AttrType)) - structPtr > this->sizeOfOptionalHeader() ){
                    throw std::logic_error("Reading data from optional header that is outside of the read range (size)");
                }

                if constexpr (std::is_pointer_v<AttrType>) return reinterpret_cast<AttrType>(attrPtr);

                return *reinterpret_cast<AttrType*>(attrPtr);

            }
            else{
                throw std::logic_error("Invalid type returned from getOptionalHeader");
            }

        }, this->getOptionalHeader());
    }

    IMAGE_DOS_HEADER* PEFile::getDosHeader(bool getEmpty){
        if(!getEmpty && !this->isTypeSet(&this->dosHeader)){
            throw std::logic_error("Dos header was not obtained before calling this method!");
        }
        return &this->dosHeader;
    }
    
    PE_STRUCTURE::ImageHeader* PEFile::getImageHeader(bool getEmpty){
        if(!getEmpty && !this->isTypeSet(&this->imageHeader)){
            throw std::logic_error("Image header was not obtained before calling this method!");
        }
        return &this->imageHeader;
    }

    HeaderVariant PEFile::getOptionalHeader(bool getEmpty){

        if( !getEmpty && !(this->isTypeSet(&this->imageOptionalHeader64) || this->isTypeSet(&this->imageOptionalHeader32)) ){
            throw std::logic_error("Optional header was not obtained before calling this method!");
        }

        if(this->getIs64Bit()) 
            return HeaderVariant(&this->imageOptionalHeader64);
        else 
            return HeaderVariant(&this->imageOptionalHeader32);
    }

    //DosHeader Data
    DWORD PEFile::headerAddress() { return this->getDosHeader()->e_lfanew; }
    WORD PEFile::magicNumber() { return this->getDosHeader()->e_magic; }
    WORD PEFile::lastPageBytes() { return this->getDosHeader()->e_cblp; }
    WORD PEFile::pagesInFile() { return this->getDosHeader()->e_cp; }
    WORD PEFile::relocations() { return this->getDosHeader()->e_crlc; }
    WORD PEFile::sizeOfHeaderInParagraphs() { return this->getDosHeader()->e_cparhdr; }
    WORD PEFile::minimumExtraParagraphs() { return this->getDosHeader()->e_minalloc; }
    WORD PEFile::maximumExtraParagraphs() { return this->getDosHeader()->e_maxalloc; }
    WORD PEFile::initialSSValue() { return this->getDosHeader()->e_ss; }
    WORD PEFile::initialSPValue() { return this->getDosHeader()->e_sp; }
    WORD PEFile::checkSum() { return this->getDosHeader()->e_csum; }
    WORD PEFile::initialIPValue() { return this->getDosHeader()->e_ip; }
    WORD PEFile::initialCSValue() { return this->getDosHeader()->e_cs; }
    WORD PEFile::addressRelocationTable() { return this->getDosHeader()->e_lfarlc; }
    WORD PEFile::overlayNumber() { return this->getDosHeader()->e_ovno; }
    WORD PEFile::oemIdentifier() { return this->getDosHeader()->e_oemid; }
    WORD PEFile::oemInformation() { return this->getDosHeader()->e_oeminfo; }

    //ImageHeader data
    DWORD PEFile::signature() { return this->getImageHeader()->signature; }
    WORD PEFile::machine() { return this->getImageHeader()->FileHeader.Machine; }
    WORD PEFile::numberOfSections() { return this->getImageHeader()->FileHeader.NumberOfSections; }
    DWORD PEFile::timeDateStamp() { return this->getImageHeader()->FileHeader.TimeDateStamp; }
    DWORD PEFile::pointerToSymbolTable() { return this->getImageHeader()->FileHeader.PointerToSymbolTable; }
    DWORD PEFile::numberOfSymbols() { return this->getImageHeader()->FileHeader.NumberOfSymbols; }
    WORD PEFile::sizeOfOptionalHeader() { return this->getImageHeader()->FileHeader.SizeOfOptionalHeader; }
    WORD PEFile::charasteristics() { return this->getImageHeader()->FileHeader.Characteristics; }

    //OptionalHeader Data
    WORD PEFile::magic() { return this->getOptHeaderAttr<WORD>(OptHeaderAttr::magic); }
    BYTE PEFile::majorLinkerVersion() { return this->getOptHeaderAttr<BYTE>(OptHeaderAttr::majorLinkerVersion); }
    BYTE PEFile::minorLinkerVersion() { return this->getOptHeaderAttr<BYTE>(OptHeaderAttr::minorLinkerVersion); }
    DWORD PEFile::sizeOfCode() { return this->getOptHeaderAttr<DWORD>(OptHeaderAttr::sizeOfCode); }
    ULONGLONG PEFile::imageBase() { return this->getOptHeaderAttr<ULONGLONG>(OptHeaderAttr::imageBase); }
    DWORD PEFile::sectionAlignment() { return this->getOptHeaderAttr<DWORD>(OptHeaderAttr::sectionAlignment); }
    DWORD PEFile::fileAlignment() { return this->getOptHeaderAttr<DWORD>(OptHeaderAttr::fileAlignment); }
    WORD PEFile::majorImageVersion() { return this->getOptHeaderAttr<WORD>(OptHeaderAttr::majorImageVersion); }
    WORD PEFile::minorImageVersion() { return this->getOptHeaderAttr<WORD>(OptHeaderAttr::minorImageVersion); }
    DWORD PEFile::win32VersionValue() { return this->getOptHeaderAttr<DWORD>(OptHeaderAttr::win32VersionValue); }
    DWORD PEFile::sizeOfImage() { return this->getOptHeaderAttr<DWORD>(OptHeaderAttr::sizeOfImage); }
    DWORD PEFile::sizeOfHeaders() { return this->getOptHeaderAttr<DWORD>(OptHeaderAttr::sizeOfHeaders); }
    DWORD PEFile::checkSumOptional() { return this->getOptHeaderAttr<DWORD>(OptHeaderAttr::checkSum); }
    WORD PEFile::subsystem() { return this->getOptHeaderAttr<WORD>(OptHeaderAttr::subsystem); }
    WORD PEFile::dllCharasteristics() { return this->getOptHeaderAttr<WORD>(OptHeaderAttr::dllCharasteristics); }
    DWORD PEFile::loaderFlags() { return this->getOptHeaderAttr<DWORD>(OptHeaderAttr::loaderFlags); }
    DWORD PEFile::numberOfRvaAndSizes() { return this->getOptHeaderAttr<DWORD>(OptHeaderAttr::numberOfRvaAndSizes); }

    WORD PEFile::majorOperatingSystemVersion(){ 
        return this->getOptHeaderAttr<WORD>(OptHeaderAttr::majorOperatingSystemVersion); 
    }
    WORD PEFile::minorOperatingSystemVersion(){ 
        return this->getOptHeaderAttr<WORD>(OptHeaderAttr::minorOperatingSystemVersion); 
    }
    ULONGLONG PEFile::sizeOfStackReserve(){ 
        return this->getOptHeaderAttr<ULONGLONG>(OptHeaderAttr::sizeOfStackReserve); 
    }
    ULONGLONG PEFile::sizeOfStackCommit(){ 
        return this->getOptHeaderAttr<ULONGLONG>(OptHeaderAttr::sizeOfStackCommit); 
    }
    ULONGLONG PEFile::sizeOfHeapReserve(){ 
        return this->getOptHeaderAttr<ULONGLONG>(OptHeaderAttr::sizeOfHeapReserve); 
    }
    ULONGLONG PEFile::sizeOfHeapCommit(){ 
        return this->getOptHeaderAttr<ULONGLONG>(OptHeaderAttr::sizeOfHeapCommit); 
    }
    WORD PEFile::majorSubsystemVersion(){ 
        return this->getOptHeaderAttr<WORD>(OptHeaderAttr::majorSubsystemVersion); 
    }
    WORD PEFile::minorSubsystemVersion(){ 
        return this->getOptHeaderAttr<WORD>(OptHeaderAttr::minorSubsystemVersion); 
    }
    DWORD PEFile::sizeOfInitializedData(){ 
        return this->getOptHeaderAttr<DWORD>(OptHeaderAttr::sizeOfInitializedData); 
    }
    DWORD PEFile::sizeOfUninitializedData(){ 
        return this->getOptHeaderAttr<DWORD>(OptHeaderAttr::sizeOfUninitializedData); 
    }
    DWORD PEFile::addressOfEntryPoint(){ 
        return this->getOptHeaderAttr<DWORD>(OptHeaderAttr::addressOfEntryPoint); 
    }
    DWORD PEFile::baseOfCode(){ 
        return this->getOptHeaderAttr<DWORD>(OptHeaderAttr::baseOfCode); 
    }
    DWORD PEFile::baseOfData(){
        if(this->getIs64Bit()) throw std::logic_error("Trying to obtain base of data on x64 PE");
        return this->getOptHeaderAttr<DWORD>(OptHeaderAttr::baseOfData);
    }
    IMAGE_DATA_DIRECTORY* PEFile::dataDirectory(){
        return this->getOptHeaderAttr<IMAGE_DATA_DIRECTORY*>(OptHeaderAttr::dataDirectory);
    }

    void PEFile::allocateSectionHeaders(std::size_t numberOfSections) {
        this->imageSectionHeaders.resize(numberOfSections);
    }

    //Data Directory (in optional header) data
    std::pair<DWORD, std::size_t> PEFile::exportDirectory() {
        return {this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_EXPORT].Size};
    }

    std::pair<DWORD, std::size_t> PEFile::importDirectory() {
        return {this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT].Size};
    }

    std::pair<DWORD, std::size_t> PEFile::resourceDirectory() {
        return {this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size};
    }

    std::pair<DWORD, std::size_t> PEFile::exceptionDirectory() {
        return {this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress, this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size};
    }

    std::pair<DWORD, std::size_t> PEFile::securityDirectory() {
        return {this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress, this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_SECURITY].Size};
    }

    std::pair<DWORD, std::size_t> PEFile::baseRelocationDirectory() {
        return {this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size};
    }

    std::pair<DWORD, std::size_t> PEFile::debugDirectory() {
        return {this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress, this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_DEBUG].Size};
    }

    std::pair<DWORD, std::size_t> PEFile::architectureDirectory() {
        return {this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress, this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size};
    }

    std::pair<DWORD, std::size_t> PEFile::globalPtrDirectory() {
        return {this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress, this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size};
    }

    std::pair<DWORD, std::size_t> PEFile::tlsDirectory() {
        return {this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_TLS].Size};
    }

    std::pair<DWORD, std::size_t> PEFile::loadConfigDirectory() {
        return {this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress, this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size};
    }

    std::pair<DWORD, std::size_t> PEFile::boundImportDirectory() {
        return {this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress, this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size};
    }

    std::pair<DWORD, std::size_t> PEFile::iatDirectory() {
        return {this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress, this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_IAT].Size};
    }

    std::pair<DWORD, std::size_t> PEFile::delayImportDescriptor() {
        return {this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress, this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size};
    }

    std::pair<DWORD, std::size_t> PEFile::clrRuntimeHeader() {
        return {this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress, this->dataDirectory()[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size};
    }

    std::pair<DWORD, std::size_t> PEFile::getDataDirectoryPairEnum(PEFile::DataDirectory dir) {
        return {this->dataDirectory()[static_cast<std::size_t>(dir)].VirtualAddress, this->dataDirectory()[static_cast<std::size_t>(dir)].Size};
    }

    //Section Headers data
    std::vector<IMAGE_SECTION_HEADER>* PEFile::getSectionHeaders(bool getEmpty) {
        if(this->imageSectionHeaders.empty()){
            throw std::logic_error("Section headers were not allocated before calling this method!");
        }
        if(!getEmpty && !this->isTypeSet(this->imageSectionHeaders.data())){
            throw std::logic_error("Section headers were not obtained before calling this method!");
        }
        return &this->imageSectionHeaders;
    }

    std::uintptr_t PEFile::getRawDirectoryAddress(DataDirectory dir) {
        auto dirPair = this->getDataDirectoryPairEnum(dir);
        if(dirPair.second == 0) throw std::logic_error("Trying to obtain raw address of empty directory");
        return this->translateRVAtoRaw(dirPair.first);
    }

    std::uintptr_t PEFile::translateRVAtoRaw(std::uintptr_t rva) {
        for(const auto& sectionHeader : *this->getSectionHeaders()){
            if(rva >= sectionHeader.VirtualAddress && rva < sectionHeader.VirtualAddress + sectionHeader.SizeOfRawData){
                return rva - sectionHeader.VirtualAddress + sectionHeader.PointerToRawData;
            }
        }

        throw std::invalid_argument("RVA not found in any section");
    }

    std::vector<IMAGE_IMPORT_DESCRIPTOR> *PEFile::getImportDirectoryTable(bool getEmpty) {
        if(!getEmpty && !this->isTypeSet(this->importDirectoryTable.data())){
            throw std::logic_error("Import directory table was not obtained before calling this method!");
        }
        return &this->importDirectoryTable;
    }

    std::vector<IMAGE_BOUND_IMPORT_DESCRIPTOR> *PEFile::getBoundImportDirectoryTable(bool getEmpty) {
        if(!getEmpty && !this->isTypeSet(this->boundImportDirectoryTable.data())){
            throw std::logic_error("Bound import directory table was not obtained before calling this method!");
        }
        return &this->boundImportDirectoryTable;
    }

    std::vector<std::string> *PEFile::getImportDirectoryNames(bool getEmpty) {
        if(!getEmpty && !this->isTypeSet(this->importDirectoryNames.data())){
            throw std::logic_error("Import directory names were not obtained before calling this method!");
        }
        return &this->importDirectoryNames;
    }

    std::vector<std::vector<std::pair<std::optional<WORD>, std::unique_ptr<IMAGE_IMPORT_BY_NAME>>>>* PEFile::getImportByNameTable(bool getEmpty) {
        if(!getEmpty && !this->isTypeSet(this->importByNameTable.data())){
            throw std::logic_error("Import by name table was not obtained before calling this method!");
        }
        return &this->importByNameTable;
    }

    std::vector<std::string> *PEFile::getBoundImportDirectoryNames(bool getEmpty) {
        if(!getEmpty && !this->isTypeSet(this->boundImportDirectoryNames.data())){
            throw std::logic_error("Bound import directory names were not obtained before calling this method!");
        }
        return &this->boundImportDirectoryNames;
    }

    std::vector<std::pair<IMAGE_BASE_RELOCATION, std::vector<WORD>>>* PEFile::getBaseRelocationTable(bool getEmpty) {
        if(!getEmpty && !this->isTypeSet(this->baseRelocationDirectoryTable.data())){
            throw std::logic_error("Base relocation directory table was not obtained before calling this method!");
        }
        return &this->baseRelocationDirectoryTable;
    }

    std::vector<IMAGE_DEBUG_DIRECTORY> *PEFile::getDebugDirectoryTable(bool getEmpty) {
        if(!getEmpty && !this->isTypeSet(this->debugDirectoryTable.data())){
            throw std::logic_error("Debug directory table was not obtained before calling this method!");
        }
        return &this->debugDirectoryTable;
    }

    ConfigVariant PEFile::getLoadConfigDirectory(bool getEmpty) {
        if(!getEmpty && !this->isTypeSet(&this->loadConfigDirectory64) && !this->isTypeSet(&this->loadConfigDirectory32)){
            throw std::logic_error("Load config directory was not obtained before calling this method!");
        }

        if(this->getIs64Bit())
            return ConfigVariant(&this->loadConfigDirectory64);
        else
            return ConfigVariant(&this->loadConfigDirectory32);
    }

    ConfigRestVariant PEFile::getLoadConfigDirectoryRest(bool getEmpty) {
        if(!getEmpty && !this->isTypeSet(&this->loadConfigDirectoryRest64) && !this->isTypeSet(&this->loadConfigDirectoryRest32)){
            throw std::logic_error("Load config directory rest was not obtained before calling this method!");
        }

        if(this->getIs64Bit())
            return ConfigRestVariant(&this->loadConfigDirectoryRest64);
        else
            return ConfigRestVariant(&this->loadConfigDirectoryRest32);
    }

    template<typename AttrType>
    AttrType PEFile::getLoadConfigData(PEFile::LoadConfigData confData){
        if(static_cast<int>(confData) > static_cast<int>(LoadConfigData::SEHandlerCount)){
            return boost::apply_visitor([&confData](auto x) -> AttrType {
                if(std::is_same_v<decltype(*x), PE_STRUCTURE::LoadConfigDirectory32_Rest&> || std::is_same_v<decltype(*x), PE_STRUCTURE::LoadConfigDirectory64_Rest&>){
                    switch(confData){
                        case LoadConfigData::GuardCFCheckFunctionPointer:
                            return x->GuardCFCheckFunctionPointer;
                        case LoadConfigData::GuardCFDispatchFunctionPointer:
                            return x->GuardCFDispatchFunctionPointer;
                        case LoadConfigData::GuardCFFunctionTable:
                            return x->GuardCFFunctionTable;
                        case LoadConfigData::GuardCFFunctionCount:
                            return x->GuardCFFunctionCount;
                        case LoadConfigData::GuardFlags:
                            return x->GuardFlags;
                        case LoadConfigData::GuardAddressTakenIatEntryTable:
                            return x->GuardAddressTakenIatEntryTable;
                        case LoadConfigData::GuardAddressTakenIatEntryCount:
                            return x->GuardAddressTakenIatEntryCount;
                        case LoadConfigData::GuardLongJumpTargetTable:
                            return x->GuardLongJumpTargetTable;
                        case LoadConfigData::GuardLongJumpTargetCount:
                            return x->GuardLongJumpTargetCount;
                        default:
                            throw std::invalid_argument("Invalid enum argument");
                    }
                }
                else{
                    throw std::logic_error("Invalid type returned from getLoadConfigDirectoryRest");
                }
            }, this->getLoadConfigDirectoryRest() );
        }

        return boost::apply_visitor([&confData](auto x) -> AttrType {
            if constexpr (std::is_same_v<decltype(*x), IMAGE_LOAD_CONFIG_DIRECTORY32&> || std::is_same_v<decltype(*x), IMAGE_LOAD_CONFIG_DIRECTORY64&>){
                switch(confData){
                    case LoadConfigData::Size:
                        return x->Size;
                    case LoadConfigData::TimeDateStamp:
                        return x->TimeDateStamp;
                    case LoadConfigData::MajorVersion:
                        return x->MajorVersion;
                    case LoadConfigData::MinorVersion:
                        return x->MinorVersion;
                    case LoadConfigData::GlobalFlagsClear:
                        return x->GlobalFlagsClear;
                    case LoadConfigData::GlobalFlagsSet:
                        return x->GlobalFlagsSet;
                    case LoadConfigData::CriticalSectionDefaultTimeout:
                        return x->CriticalSectionDefaultTimeout;
                    case LoadConfigData::DeCommitFreeBlockThreshold:
                        return x->DeCommitFreeBlockThreshold;
                    case LoadConfigData::DeCommitTotalFreeThreshold:
                        return x->DeCommitTotalFreeThreshold;
                    case LoadConfigData::LockPrefixTable:
                        return x->LockPrefixTable;
                    case LoadConfigData::MaximumAllocationSize:
                        return x->MaximumAllocationSize;
                    case LoadConfigData::VirtualMemoryThreshold:
                        return x->VirtualMemoryThreshold;
                    case LoadConfigData::ProcessAffinityMask:
                        return x->ProcessAffinityMask;
                    case LoadConfigData::ProcessHeapFlags:
                        return x->ProcessHeapFlags;
                    case LoadConfigData::CSDVersion:
                        return x->CSDVersion;
                    case LoadConfigData::DependentLoadFlags:
                        return x->Reserved1;
                    case LoadConfigData::EditList:
                        return x->EditList;
                    case LoadConfigData::SecurityCookie:
                        return x->SecurityCookie;
                    case LoadConfigData::SEHandlerTable:
                        return x->SEHandlerTable;
                    case LoadConfigData::SEHandlerCount:
                        return x->SEHandlerCount;
                    default:
                        throw std::invalid_argument("Invalid enum argument");
                }
            }
            else{
                throw std::logic_error("Invalid type returned from getLoadConfigDirectory");
            }
        }, this->getLoadConfigDirectory() );
    }

    DWORD PEFile::LoadConfigSize() {
        return this->getLoadConfigData<DWORD>(LoadConfigData::Size);
    }

    DWORD PEFile::LoadConfigTimeDateStamp() {
        return this->getLoadConfigData<DWORD>(LoadConfigData::TimeDateStamp);
    }

    WORD PEFile::LoadConfigMajorVersion() {
        return this->getLoadConfigData<WORD>(LoadConfigData::MajorVersion);
    }

    WORD PEFile::LoadConfigMinorVersion() {
        return this->getLoadConfigData<WORD>(LoadConfigData::MinorVersion);
    }

    DWORD PEFile::LoadConfigGlobalFlagsClear() {
        return this->getLoadConfigData<DWORD>(LoadConfigData::GlobalFlagsClear);
    }

    DWORD PEFile::LoadConfigGlobalFlagsSet() {
        return this->getLoadConfigData<DWORD>(LoadConfigData::GlobalFlagsSet);
    }

    DWORD PEFile::LoadConfigCriticalSectionDefaultTimeout() {
        return this->getLoadConfigData<DWORD>(LoadConfigData::CriticalSectionDefaultTimeout);
    }

    ULONGLONG PEFile::LoadConfigDeCommitFreeBlockThreshold() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::DeCommitFreeBlockThreshold);
    }

    ULONGLONG PEFile::LoadConfigDeCommitTotalFreeThreshold() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::DeCommitTotalFreeThreshold);
    }

    ULONGLONG PEFile::LoadConfigLockPrefixTable() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::LockPrefixTable);
    }

    ULONGLONG PEFile::LoadConfigMaximumAllocationSize() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::MaximumAllocationSize);
    }

    ULONGLONG PEFile::LoadConfigVirtualMemoryThreshold() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::VirtualMemoryThreshold);
    }

    ULONGLONG PEFile::LoadConfigProcessAffinityMask() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::ProcessAffinityMask);
    }

    DWORD PEFile::LoadConfigProcessHeapFlags() {
        return this->getLoadConfigData<DWORD>(LoadConfigData::ProcessHeapFlags);
    }

    WORD PEFile::LoadConfigCSDVersion() {
        return this->getLoadConfigData<WORD>(LoadConfigData::CSDVersion);
    }

    ULONGLONG PEFile::LoadConfigSecurityCookie() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::SecurityCookie);
    }

    ULONGLONG PEFile::LoadConfigSEHandlerTable() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::SEHandlerTable);
    }

    ULONGLONG PEFile::LoadConfigSEHandlerCount() {
        return this->getLoadConfigData<WORD>(LoadConfigData::SEHandlerCount);
    }

    ULONGLONG PEFile::LoadConfigGuardCFCheckFunctionPointer() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::GuardCFCheckFunctionPointer);
    }

    ULONGLONG PEFile::LoadConfigGuardCFDispatchFunctionPointer() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::GuardCFDispatchFunctionPointer);
    }

    ULONGLONG PEFile::LoadConfigGuardCFFunctionTable() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::GuardCFFunctionTable);
    }

    ULONGLONG PEFile::LoadConfigGuardCFFunctionCount() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::GuardCFFunctionCount);
    }

    DWORD PEFile::LoadConfigGuardFlags() {
        return this->getLoadConfigData<DWORD>(LoadConfigData::GuardFlags);
    }

    DWORD* PEFile::LoadConfigCodeIntegrity() {
        return boost::apply_visitor([](auto x) -> DWORD* {
            if constexpr (std::is_same_v<decltype(*x), PE_STRUCTURE::LoadConfigDirectory32_Rest&> || std::is_same_v<decltype(*x), PE_STRUCTURE::LoadConfigDirectory64_Rest&>){
                return x->CodeIntegrity;
            }
            else{
                throw std::logic_error("Invalid type returned from getLoadConfigDirectoryRest");
            }
        }, this->getLoadConfigDirectoryRest() );
    }

    ULONGLONG PEFile::LoadConfigGuardAddressTakenIatEntryTable() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::GuardAddressTakenIatEntryTable);
    }

    ULONGLONG PEFile::LoadConfigGuardAddressTakenIatEntryCount() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::GuardAddressTakenIatEntryCount);
    }

    ULONGLONG PEFile::LoadConfigGuardLongJumpTargetTable() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::GuardLongJumpTargetTable);
    }

    ULONGLONG PEFile::LoadConfigGuardLongJumpTargetCount() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::GuardLongJumpTargetCount);
    }

    ULONGLONG PEFile::LoadConfigEditList() {
        return this->getLoadConfigData<ULONGLONG>(LoadConfigData::EditList);
    }

    WORD PEFile::LoadConfigDependentLoadFlags() {
        return this->getLoadConfigData<WORD>(LoadConfigData::DependentLoadFlags);
    }

    TLSVariant PEFile::getTLSDirectory(bool getEmpty) {
        if(!getEmpty && !this->isTypeSet(&this->tlsDirectory32) && !this->isTypeSet(&this->tlsDirectory64)){
            throw std::logic_error("TLS directory was not obtained before calling this method!");
        }

        if(this->getIs64Bit()) {
            return TLSVariant(&this->tlsDirectory64);
        }
        else{
            return TLSVariant(&this->tlsDirectory32);
        }

    }

    template<typename AttrType>
    AttrType PEFile::getTLSData(PEFile::TLSData tlsData){
        return boost::apply_visitor([&tlsData](auto x) -> AttrType {
            if constexpr (std::is_same_v<decltype(*x), IMAGE_TLS_DIRECTORY32&> || std::is_same_v<decltype(*x), IMAGE_TLS_DIRECTORY64&>){
                switch(tlsData){
                    case TLSData::StartAddressOfRawData:
                        return x->StartAddressOfRawData;
                    case TLSData::EndAddressOfRawData:
                        return x->EndAddressOfRawData;
                    case TLSData::AddressOfIndex:
                        return x->AddressOfIndex;
                    case TLSData::AddressOfCallBacks:
                        return x->AddressOfCallBacks;
                    case TLSData::SizeOfZeroFill:
                        return x->SizeOfZeroFill;
                    case TLSData::Characteristics:
                        return x->Characteristics;
                    default:
                        throw std::invalid_argument("Invalid enum argument");
                }
            }
            else{
                throw std::logic_error("Invalid type returned from getTLSDirectory");
            }
        }, this->getTLSDirectory() );
    }

    ULONGLONG PEFile::tlsStartAddressOfRawData() {
        return this->getTLSData<ULONGLONG>(TLSData::StartAddressOfRawData);
    }

    ULONGLONG PEFile::tlsEndAddressOfRawData() {
        return this->getTLSData<ULONGLONG>(TLSData::EndAddressOfRawData);
    }

    ULONGLONG PEFile::tlsAddressOfIndex() {
        return this->getTLSData<ULONGLONG>(TLSData::AddressOfIndex);
    }

    ULONGLONG PEFile::tlsAddressOfCallBacks() {
        return this->getTLSData<ULONGLONG>(TLSData::AddressOfCallBacks);
    }

    ULONGLONG PEFile::tlsSizeOfZeroFill() {
        return this->getTLSData<ULONGLONG>(TLSData::SizeOfZeroFill);
    }

    ULONGLONG PEFile::tlsCharacteristics() {
        return this->getTLSData<ULONGLONG>(TLSData::Characteristics);
    }
};