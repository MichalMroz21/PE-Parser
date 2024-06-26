#include <Parser.hpp>

namespace PE_PARSER{

    Parser::Parser() = default;

    void Parser::freeBuffer(){
        if(this->buffer)
            free(this->buffer);
        this->buffer = nullptr;
    }

    Parser::~Parser(){
        freeBuffer();
    }

    //using this instead of memcpy with struct, because in case of big endian recursive struct iteration is needed
    template<typename Base, class Md>
    void Parser::copyBytesToStruct(Base& base, long long toCopy){
        boost::mp11::mp_for_each<Md>([&](auto attr){
            if(toCopy <= 0) return;
            this->copyBytesToStructInner(base.*attr.pointer, toCopy);
            toCopy -= sizeof(attr);   
        });
    }

    template<typename Arr> 
    void Parser::copyBytesToStructInnerArr(Arr& arr, long long toCopy){
        for (auto& el : arr){
            if(toCopy <= 0) return;
            this->copyBytesToStructInner(el, toCopy);
            toCopy -= sizeof(el);
        }
    }

    template<typename Attr> 
    void Parser::copyBytesToVariable(Attr& attr){
        int bytesToGet = sizeof(Attr);

        if (this->buffer->availableToCopy() < bytesToGet){
            throw std::logic_error("Trying to read from a buffer that has no more data to copy from");
        }

        if(!PE_PARSER::Parser::isBigEndian){
            std::memcpy(&attr, this->buffer->getBeginAddress(), bytesToGet);
        }
        else{
            std::reverse_copy(reinterpret_cast<const char*>(this->buffer->getBeginAddress()),
                reinterpret_cast<const char*>(this->buffer->getBeginAddress() + bytesToGet), reinterpret_cast<char*>(&attr));
        } 
            
        this->buffer->cutBytes(bytesToGet);
    }

    template<typename Attr> 
    void Parser::copyBytesToStructInner(Attr& attr, long long toCopy){
        //check if iterated type is struct, if it is then recursively call this function for it
        if constexpr (std::is_class_v<Attr>){
            this->copyBytesToStruct(attr, toCopy);
        }
        else if constexpr (std::is_array_v<Attr>){
            this->copyBytesToStructInnerArr(attr, toCopy);
        }
        else if(toCopy >= sizeof(attr)){
            this->copyBytesToVariable(attr);
        }
    }

    std::string Parser::getNullTerminatedString(){
        std::string str{};

        while(true){
            char c{};
            this->copyBytesToVariable(c);
            if(c == '\0') break;
            str += c;
        }

        return str;
    }

    template<typename Strct, typename Arr>
    void Parser::getStructsNullTerminated(Arr *arr, PE_DATA::PEFile* peFile) {
        while (true) {
            Strct strct{};
            if constexpr(std::is_array_v<Strct>) this->copyBytesToStruct(strct);
            else this->copyBytesToVariable(strct);
            if (!peFile->isTypeSet(&strct)) break;
            arr->push_back(strct);
        }
    }

    template<typename Strct, typename Arr>
    void Parser::getStructs(Arr *arr, PE_DATA::PEFile *peFile, const std::size_t amount) {
        for (std::size_t i = 0; i < amount; i++){
            Strct strct{};
            if constexpr(std::is_array_v<Strct>) this->copyBytesToStruct(strct);
            else this->copyBytesToVariable(strct);
            arr->push_back(strct);
        }
    }

    void Parser::getBoundImportDirectoryData(PE_DATA::PEFile* peFile){
        this->buffer->setMemoryLocation(peFile->getRawDirectoryAddress(PE_DATA::PEFile::DataDirectory::boundImportDirectory));

        //Get Bound Import Directory Table
        while(true){
            IMAGE_BOUND_IMPORT_DESCRIPTOR boundImportRow{};
            this->buffer->cutBytes(sizeof(IMAGE_BOUND_FORWARDER_REF) * boundImportRow.NumberOfModuleForwarderRefs);
            this->copyBytesToStruct(boundImportRow);
            if(!peFile->isTypeSet(&boundImportRow)) break;
            peFile->getBoundImportDirectoryTable(true)->push_back(boundImportRow);
        }

        //Get DLL names from Bound Import Directory Table
        for(const auto& boundRow : *peFile->getBoundImportDirectoryTable()){
            this->buffer->setMemoryLocation(peFile->getRawDirectoryAddress(PE_DATA::PEFile::DataDirectory::boundImportDirectory));
            this->buffer->cutBytes(boundRow.OffsetModuleName);
            peFile->getBoundImportDirectoryNames(true)->push_back(this->getNullTerminatedString());
        }
    }

    void Parser::getImportDirectoryData(PE_DATA::PEFile* peFile){
        this->buffer->setMemoryLocation(peFile->getRawDirectoryAddress(PE_DATA::PEFile::DataDirectory::importDirectory));

        //Get Import Directory Table
        this->getStructsNullTerminated<IMAGE_IMPORT_DESCRIPTOR>(peFile->getImportDirectoryTable(true), peFile);

        //Get Import Directory Names
        for (const auto &importRow: *peFile->getImportDirectoryTable()){
            this->buffer->setMemoryLocation(peFile->translateRVAtoRaw(importRow.Name));
            peFile->getImportDirectoryNames(true)->push_back(this->getNullTerminatedString());
        }

        //Obtain Import Lookup Tables for Imports
        for (const auto &importRow: *peFile->getImportDirectoryTable()){
            this->buffer->setMemoryLocation(peFile->translateRVAtoRaw(importRow.OriginalFirstThunk));
            peFile->getImportByNameTable(true)->emplace_back();

            while (boost::apply_visitor([this, peFile](auto x) -> bool{
                this->copyBytesToVariable(*x);
                if (*x == 0) return false;

                std::unique_ptr<IMAGE_IMPORT_BY_NAME> importByName{};
                std::optional<WORD> ordinal{};

                if ((*x >> (sizeof(*x) * CHAR_BIT - 1)) & 1) {
                    ordinal = *x & 0x7FFFFFFF;
                } else {
                    DWORD savedLocation = this->buffer->getCurrMemoryLocation();
                    WORD hint{};

                    this->buffer->setMemoryLocation(peFile->translateRVAtoRaw(*x));

                    this->copyBytesToVariable(hint);
                    std::string name = this->getNullTerminatedString();

                    importByName = std::unique_ptr<IMAGE_IMPORT_BY_NAME>((IMAGE_IMPORT_BY_NAME *) malloc(sizeof(IMAGE_IMPORT_BY_NAME) - 1 + name.size()));
                    importByName->Hint = hint;

                    std::memcpy(importByName->Name, name.c_str(), name.size() + 1);
                    this->buffer->setMemoryLocation(savedLocation);
                }

                peFile->getImportByNameTable(true)->back().emplace_back(ordinal, std::move(importByName));
                return true;
            }, peFile->getILTEntryVariant(true))) {}
        }
    }

    void Parser::getBaseRelocationDirectoryData(PE_DATA::PEFile *peFile){
        this->buffer->setMemoryLocation(peFile->getRawDirectoryAddress(PE_DATA::PEFile::DataDirectory::baseRelocationDirectory));

        while(true){
            IMAGE_BASE_RELOCATION baseRelocation{};
            this->copyBytesToStruct(baseRelocation);

            if(!peFile->isTypeSet(&baseRelocation)) break;

            peFile->getBaseRelocationTable(true)->emplace_back(baseRelocation, std::vector<WORD>{});

            this->getStructs<WORD>(&peFile->getBaseRelocationTable(true)->back().second, peFile,  (baseRelocation.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD));
        }
    }

    void Parser::getDebugDirectoryData(PE_DATA::PEFile *peFile) {
        this->buffer->setMemoryLocation(peFile->getRawDirectoryAddress(PE_DATA::PEFile::DataDirectory::debugDirectory));
        this->getStructs<IMAGE_DEBUG_DIRECTORY>(peFile->getDebugDirectoryTable(true), peFile,  peFile->debugDirectory().second / sizeof(IMAGE_DEBUG_DIRECTORY));
    }

    void Parser::getLoadConfigDirectoryData(PE_DATA::PEFile *peFile) {
        this->buffer->setMemoryLocation(peFile->getRawDirectoryAddress(PE_DATA::PEFile::DataDirectory::loadConfigDirectory));
        std::size_t sizeOfLoadConfigDirectory = peFile->loadConfigDirectory().second;

        if(boost::apply_visitor([this, peFile, &sizeOfLoadConfigDirectory](auto x) -> bool{
            this->copyBytesToStruct(*x, std::min(sizeOfLoadConfigDirectory, sizeof(*x)));
            bool noRest = sizeOfLoadConfigDirectory <= sizeof(*x);
            sizeOfLoadConfigDirectory -= sizeof(*x);
            return noRest;
        }, peFile->getLoadConfigDirectory(true))) return;

        boost::apply_visitor([this, peFile, sizeOfLoadConfigDirectory](auto x){
            this->copyBytesToStruct(*x, std::min(sizeOfLoadConfigDirectory, sizeof(*x)));
        }, peFile->getLoadConfigDirectoryRest(true));
    }

    void Parser::getTLSDirectoryData(PE_DATA::PEFile *peFile) {
        this->buffer->setMemoryLocation(peFile->getRawDirectoryAddress(PE_DATA::PEFile::DataDirectory::tlsDirectory));

        boost::apply_visitor([this, peFile](auto x){
            this->copyBytesToStruct(*x);
            if(x->AddressOfCallBacks != 0){
                this->buffer->setMemoryLocation(peFile->translateVAtoRaw(x->AddressOfCallBacks));
                this->getStructsNullTerminated<PIMAGE_TLS_CALLBACK>(peFile->getTLSCallbacks(true), peFile);
            }
        }, peFile->getTLSDirectory(true));
    }

    template<typename T>
    void Parser::getExceptionStructs(std::vector<T>* exceptionDirectory, PE_DATA::PEFile* peFile){
        this->getStructsNullTerminated<T>(exceptionDirectory, peFile);
    }

    void Parser::getExceptionDirectoryData(PE_DATA::PEFile *peFile) {
        this->buffer->setMemoryLocation(peFile->getRawDirectoryAddress(PE_DATA::PEFile::DataDirectory::exceptionDirectory));

        boost::apply_visitor([this, peFile](auto x){
            this->getExceptionStructs(x, peFile);
        }, peFile->getExceptionDirectory(true));
    }

    void Parser::getSecurityDirectoryData(PE_DATA::PEFile *peFile) {
        this->buffer->setMemoryLocation(peFile->securityDirectory().first);

        std::size_t totalLength = peFile->securityDirectory().second;

        while(true){
            DWORD length{};

            this->copyBytesToVariable<DWORD>(length);
            this->buffer->uncutBytes(sizeof(length));

            auto secRow = std::unique_ptr<WIN_CERTIFICATE>((WIN_CERTIFICATE*)(malloc(length)));

            this->copyBytesToStruct(*secRow);
            std::memcpy(secRow->bCertificate, this->buffer->getBeginAddress() - sizeof(BYTE), length - 2 * sizeof(DWORD));

            peFile->getSecurityTable(true)->push_back(std::move(secRow));

            if(totalLength <= length) break;
            totalLength -= length;
        }
    }

    PE_DATA::PEFile* Parser::loadPEFile(){
        auto* peFile = new PE_DATA::PEFile();

        //Copy Dos Header
        this->copyBytesToStruct(*peFile->getDosHeader(true));

        this->buffer->setMemoryLocation(peFile->headerAddress());

        //Copy Image Header
        this->copyBytesToStruct(*peFile->getImageHeader(true));

        //Allocate space for section headers
        peFile->allocateSectionHeaders(peFile->numberOfSections());

        //The type of Optional Header
        DWORD stateOfMachine{};

        this->copyBytesToVariable(stateOfMachine);
        this->buffer->uncutBytes(sizeof(stateOfMachine));

        peFile->setTypeOfPE(stateOfMachine);

        boost::apply_visitor([this, peFile](auto x){
            this->copyBytesToStruct(*x, peFile->sizeOfOptionalHeader());
        }, peFile->getOptionalHeader(true));

        //Copy Section Headers
        for(auto& imageSectionHeader : *peFile->getSectionHeaders(true)){
            this->copyBytesToStruct(imageSectionHeader);
        }

        //Get Data Directories
        if(peFile->getDataDirectoryPairEnum(PE_DATA::PEFile::DataDirectory::importDirectory).second){
            this->getImportDirectoryData(peFile); //!Leaves buffer at random address
        }

        if(peFile->getDataDirectoryPairEnum(PE_DATA::PEFile::DataDirectory::boundImportDirectory).second){
            this->getBoundImportDirectoryData(peFile); //!Leaves buffer at random address
        }

        if(peFile->getDataDirectoryPairEnum(PE_DATA::PEFile::DataDirectory::baseRelocationDirectory).second){
            this->getBaseRelocationDirectoryData(peFile); //!Leaves buffer at random address
        }

        if(peFile->getDataDirectoryPairEnum(PE_DATA::PEFile::DataDirectory::debugDirectory).second){
            this->getDebugDirectoryData(peFile); //!Leaves buffer at random address
        }

        if(peFile->getDataDirectoryPairEnum(PE_DATA::PEFile::DataDirectory::loadConfigDirectory).second){
            this->getLoadConfigDirectoryData(peFile); //!Leaves buffer at random address
        }

        if(peFile->getDataDirectoryPairEnum(PE_DATA::PEFile::DataDirectory::tlsDirectory).second){
            this->getTLSDirectoryData(peFile); //!Leaves buffer at random address
        }

        if(peFile->getDataDirectoryPairEnum(PE_DATA::PEFile::DataDirectory::exceptionDirectory).second){
            this->getExceptionDirectoryData(peFile); //!Leaves buffer at random address
        }

        if(peFile->getDataDirectoryPairEnum(PE_DATA::PEFile::DataDirectory::securityDirectory).second){
           this->getSecurityDirectoryData(peFile); //!Leaves buffer at random address
        }

        this->freeBuffer();
        return peFile;
    }

    PE_DATA::PEFile* Parser::loadPEFileFromPath(const char* fullPEPath){
        this->freeBuffer();
        this->buffer = new PE_BUFFER::Buffer(fullPEPath);
        return this->loadPEFile();
    }

    PE_DATA::PEFile* Parser::loadPEFileFromBytes(const std::vector<BYTE>& bytes){
        this->freeBuffer();
        this->buffer = new PE_BUFFER::Buffer(bytes);
        return this->loadPEFile();
    }

    PE_DATA::PEFile* Parser::loadPEFileFromHexString(const std::string& hexStr){
        this->freeBuffer();
        this->buffer = new PE_BUFFER::Buffer(hexStr);
        return this->loadPEFile();
    }
};