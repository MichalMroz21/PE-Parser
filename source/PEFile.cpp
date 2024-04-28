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

                return *reinterpret_cast<AttrType*>(attrPtr);
            }
            else{
                throw std::logic_error("Invalid type returned from getOptionalHeader");
            }

        }, this->getOptionalHeader());
    }

    //Data Structs
    PE_STRUCTURE::DosHeader PEFile::getDosHeaderStruct(){
        return this->dosHeader;
    }
    
    PE_STRUCTURE::ImageHeader PEFile::getImageHeaderStruct(){
        return this->imageHeader;
    }

    HeaderVariant PEFile::getOptionalHeader(){
        if(this->getIs64Bit()) 
            return HeaderVariant(&this->imageOptionalHeader64);
        else 
            return HeaderVariant(&this->imageOptionalHeader32);
    }

    //DosHeader Data
    DWORD PEFile::headerAddress() { return this->dosHeader.e_lfanew; }
    WORD PEFile::magicNumber() { return this->dosHeader.magic; }
    WORD PEFile::lastPageBytes() { return this->dosHeader.e_cblp; }
    WORD PEFile::pagesInFile() { return this->dosHeader.e_cp; }
    WORD PEFile::relocations() { return this->dosHeader.e_crlc; }
    WORD PEFile::sizeOfHeaderInParagraphs() { return this->dosHeader.e_cparhdr; }
    WORD PEFile::minimumExtraParagraphs() { return this->dosHeader.e_minalloc; }
    WORD PEFile::maximumExtraParagraphs() { return this->dosHeader.e_maxalloc; }
    WORD PEFile::initialSSValue() { return this->dosHeader.e_ss; }
    WORD PEFile::initialSPValue() { return this->dosHeader.e_sp; }
    WORD PEFile::checkSum() { return this->dosHeader.e_csum; }
    WORD PEFile::initialIPValue() { return this->dosHeader.e_ip; }
    WORD PEFile::initialCSValue() { return this->dosHeader.e_cs; }
    WORD PEFile::addressRelocationTable() { return this->dosHeader.e_lfarlc; }
    WORD PEFile::overlayNumber() { return this->dosHeader.e_ovno; }
    WORD PEFile::oemIdentifier() { return this->dosHeader.e_oemid; }
    WORD PEFile::oemInformation() { return this->dosHeader.e_oeminfo; }

    //ImageHeader data
    DWORD PEFile::signature() { return this->imageHeader.signature; }
    WORD PEFile::machine() { return this->imageHeader.FileHeader.Machine; }
    WORD PEFile::numberOfSections() { return this->imageHeader.FileHeader.NumberOfSections; }
    DWORD PEFile::timeDateStamp() { return this->imageHeader.FileHeader.TimeDateStamp; }
    DWORD PEFile::pointerToSymbolTable() { return this->imageHeader.FileHeader.PointerToSymbolTable; }
    DWORD PEFile::numberOfSymbols() { return this->imageHeader.FileHeader.NumberOfSymbols; }
    WORD PEFile::sizeOfOptionalHeader() { return this->imageHeader.FileHeader.SizeOfOptionalHeader; }
    WORD PEFile::charasteristics() { return this->imageHeader.FileHeader.Characteristics; }

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

    //Section Headers data
    std::vector<IMAGE_SECTION_HEADER> PEFile::getSectionHeaders() {
        return this->imageSectionHeaders;
    }
};