#include <PEFile.hpp>

namespace PE_DATA{
    PEFile::PEFile(){}

    void PEFile::setTypeOfPE(WORD stateOfMachine){
        if(stateOfMachine == 0x010B) this->is64Bit = false;
        else if(stateOfMachine == 0x020B) this->is64Bit = true;
        else{
            throw std::invalid_argument("Invalid or unsupported stateOfMachine!");
        }
        
        this->wasTypeSet = true;
    }

    bool PEFile::is64Bit(){
        if(!this->wasTypeSet){
            throw std::logic_error("Type of PE was not set before calling this method!");
        }
        return this->is64Bit;
    }

    ULONGLONG PEFile::getOptHeaderAttr(OptHeaderAttr attr, int attrSize){

        return boost::apply_visitor([attr, attrSize, this](auto x) -> ULONGLONG {

            std::uintptr_t attrPtr{}, structPtr = reinterpret_cast<std::uintptr_t>(x);

            switch(attr){

                using namespace OptHeaderAttr;

                case magic:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->magic);
                    break;
                case majorLinkerVersion:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->majorLinkerVersion);
                    break;
                case minorLinkerVersion:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->minorLinkerVersion);
                    break;
                case sizeOfCode:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->sizeOfCode);
                    break;
                case sizeOfInitializedData:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->sizeOfInitializedData);
                    break;
                case sizeOfUninitializedData:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->sizeOfUninitializedData);
                    break;
                case addressOfEntryPoint:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->addressOfEntryPoint);
                    break;
                case baseOfCode:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->baseOfCode);
                    break;
                case baseOfData:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->baseOfData);
                    break;
                case imageBase:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->imageBase);
                    break;
                case sectionAlignment:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->sectionAlignment);
                    break;
                case fileAlignment:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->fileAlignment);
                    break;
                case majorOperatingSystemVersion:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->majorOperatingSystemVersion);
                    break;
                case minorOperatingSystemVersion:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->minorOperatingSystemVersion);
                    break;
                case majorImageVersion:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->majorImageVersion);
                    break;
                case minorImageVersion:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->minorImageVersion);
                    break;
                case majorSubsystemVersion:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->majorSubsystemVersion);
                    break;
                case minorSubsystemVersion:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->minorSubsystemVersion);
                    break;
                case win32VersionValue:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->win32VersionValue);
                    break;
                case sizeOfImage:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->sizeOfImage);
                    break;
                case sizeOfHeaders:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->sizeOfHeaders);
                    break;
                case checkSum:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->checkSum);
                    break;
                case subsystem:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->subsystem);
                    break;
                case dllCharasteristics:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->dllCharasteristics);
                    break;
                case sizeOfStackReserve:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->sizeOfStackReserve);
                    break;
                case sizeOfStackCommit:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->sizeOfStackCommit);
                    break;
                case sizeOfHeapReserve:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->sizeOfHeapReserve);
                    break;
                case sizeOfHeapCommit:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->sizeOfHeapCommit);
                    break;
                case loaderFlags:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->loaderFlags);
                    break;
                case numberOfRvaAndSizes:
                    attrPtr = reinterpret_cast<std::uintptr_t>(&x->numberOfRvaAndSizes);
                    break;
                default:
                    throw std::invalid_argument("Invalid enum argument");
            }

            if( (attrPtr + attrSize) - structPtr > this->sizeOfOptionalHeader() ){
                throw std::logic_error("Reading data from optional header that is outside of the read range (size)");
            }

            return *reinterpret_cast<ULONGLONG*>(attrPtr);

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
        if(this->is64Bit()) 
            return HeaderVariant(&this->imageOptionalHeader64);
        else 
            return HeaderVariant(&this->imageOptionalHeader32);
    }

    //DosHeader Data
    DWORD PEFile::headerAddress(){
        return this->dosHeader.e_lfanew;
    }

    WORD PEFile::magicNumber(){
        return this->dosHeader.magic;
    }

    WORD PEFile::lastPageBytes(){
        return this->dosHeader.e_cblp;
    }

    WORD PEFile::pagesInFile(){
        return this->dosHeader.e_cp;
    }

    WORD PEFile::relocations(){
        return this->dosHeader.e_crlc;
    }

    WORD PEFile::sizeOfHeaderInParagraphs(){
        return this->dosHeader.e_cparhdr;
    }

    WORD PEFile::minimumExtraParagraphs(){
        return this->dosHeader.e_minalloc;
    }

    WORD PEFile::maximumExtraParagraphs(){
        return this->dosHeader.e_maxalloc;
    }

    WORD PEFile::initialSSValue(){
        return this->dosHeader.e_ss;
    }

    WORD PEFile::initialSPValue(){
        return this->dosHeader.e_sp;
    }

    WORD PEFile::checkSum(){
        return this->dosHeader.e_csum;
    }

    WORD PEFile::initialIPValue(){
        return this->dosHeader.e_ip;
    }

    WORD PEFile::initialCSValue(){
        return this->dosHeader.e_cs;
    }

    WORD PEFile::addressRelocationTable(){
        return this->dosHeader.e_lfarlc;
    }

    WORD PEFile::overlayNumber(){
        return this->dosHeader.e_ovno;
    }

    WORD PEFile::oemIdentifier(){
        return this->dosHeader.e_oemid;
    }

    WORD PEFile::oemInformation(){
        return this->dosHeader.e_oeminfo;
    }

    //ImageHeader data
    DWORD PEFile::signature(){
        return this->imageHeader.signature;
    }

    WORD PEFile::machine(){
        return this->imageHeader.FileHeader.Machine;
    }

    WORD PEFile::numberOfSections(){
        return this->imageHeader.FileHeader.NumberOfSections;
    }

    DWORD PEFile::timeDateStamp(){
        return this->imageHeader.FileHeader.TimeDateStamp;
    }

    DWORD PEFile::pointerToSymbolTable(){
        return this->imageHeader.FileHeader.PointerToSymbolTable;
    }

    DWORD PEFile::numberOfSymbols(){
        return this->imageHeader.FileHeader.NumberOfSymbols;
    }

    WORD PEFile::sizeOfOptionalHeader(){
        return this->imageHeader.FileHeader.SizeOfOptionalHeader;
    }

    WORD PEFile::charasteristics(){
        return this->imageHeader.FileHeader.Characteristics;
    }

    //OptionalHeader Data
    WORD PEFile::magic(){
        return static_cast<WORD>(this->getOptHeaderAttr(OptHeaderAttr::magic, sizeof(WORD)));
    }

    BYTE PEFile::majorLinkerVersion(){
        return static_cast<BYTE>(this->getOptHeaderAttr(OptHeaderAttr::majorLinkerVersion, sizeof(BYTE)));
    }

    BYTE PEFile::minorLinkerVersion(){
        return static_cast<BYTE>(this->getOptHeaderAttr(OptHeaderAttr::minorLinkerVersion, sizeof(BYTE)));
    }

    DWORD PEFile::sizeOfCode(){
        return static_cast<DWORD>(this->getOptHeaderAttr(OptHeaderAttr::sizeOfCode, sizeof(DWORD)));
    }

    DWORD PEFile::sizeOfInitializedData(){
        return static_cast<DWORD>(this->getOptHeaderAttr(OptHeaderAttr::sizeOfInitializedData, sizeof(DWORD)));
    }

    DWORD PEFile::sizeOfUninitializedData(){
        return static_cast<DWORD>(this->getOptHeaderAttr(OptHeaderAttr::sizeOfUninitializedData, sizeof(DWORD)));
    }

    DWORD PEFile::addressOfEntryPoint(){
        return static_cast<DWORD>(this->getOptHeaderAttr(OptHeaderAttr::addressOfEntryPoint, sizeof(DWORD)));
    }

    DWORD PEFile::baseOfCode(){
        return static_cast<DWORD>(this->getOptHeaderAttr(OptHeaderAttr::baseOfCode, sizeof(DWORD)));
    }

    DWORD PEFile::baseOfData(){
        return static_cast<DWORD>(this->getOptHeaderAttr(OptHeaderAttr::baseOfData, sizeof(DWORD)));
    }

    ULONGLONG PEFile::imageBase(){
        return this->getOptHeaderAttr(OptHeaderAttr::imageBase, sizeof(ULONGLONG));
    }

    DWORD PEFile::sectionAlignment(){
        return static_cast<DWORD>(this->getOptHeaderAttr(OptHeaderAttr::sectionAlignment, sizeof(DWORD)));
    }

    DWORD PEFile::fileAlignment(){
        return static_cast<DWORD>(this->getOptHeaderAttr(OptHeaderAttr::fileAlignment, sizeof(DWORD)));
    }

    WORD PEFile::majorOperatingSystemVersion(){
        return static_cast<WORD>(this->getOptHeaderAttr(OptHeaderAttr::majorOperatingSystemVersion, sizeof(WORD)));
    }

    WORD PEFile::minorOperatingSystemVersion(){
        return static_cast<WORD>(this->getOptHeaderAttr(OptHeaderAttr::minorOperatingSystemVersion, sizeof(WORD)));
    }

    WORD PEFile::majorImageVersion(){
        return static_cast<WORD>(this->getOptHeaderAttr(OptHeaderAttr::majorImageVersion, sizeof(WORD)));
    }

    WORD PEFile::minorImageVersion(){
        return static_cast<WORD>(this->getOptHeaderAttr(OptHeaderAttr::minorImageVersion, sizeof(WORD)));
    }

    WORD PEFile::majorSubsystemVersion(){
        return static_cast<WORD>(this->getOptHeaderAttr(OptHeaderAttr::majorSubsystemVersion, sizeof(WORD)));
    }

    WORD PEFile::minorSubsystemVersion(){
        return static_cast<WORD>(this->getOptHeaderAttr(OptHeaderAttr::minorSubsystemVersion, sizeof(WORD)));
    }

    DWORD PEFile::win32VersionValue(){
        return static_cast<DWORD>(this->getOptHeaderAttr(OptHeaderAttr::win32VersionValue, sizeof(DWORD)));
    }

    DWORD PEFile::sizeOfImage(){
        return static_cast<DWORD>(this->getOptHeaderAttr(OptHeaderAttr::sizeOfImage, sizeof(DWORD)));
    }

    DWORD PEFile::sizeOfHeaders(){
        return static_cast<DWORD>(this->getOptHeaderAttr(OptHeaderAttr::sizeOfHeaders, sizeof(DWORD)));
    }

    DWORD PEFile::checkSumOptional(){
        return static_cast<DWORD>(this->getOptHeaderAttr(OptHeaderAttr::checkSum, sizeof(DWORD)));
    }

    WORD PEFile::subsystem(){
        return static_cast<WORD>(this->getOptHeaderAttr(OptHeaderAttr::subsystem, sizeof(WORD)));
    }

    WORD PEFile::dllCharasteristics(){
        return static_cast<WORD>(this->getOptHeaderAttr(OptHeaderAttr::dllCharasteristics, sizeof(WORD)));
    }

    ULONGLONG PEFile::sizeOfStackReserve(){
        return this->getOptHeaderAttr(OptHeaderAttr::sizeOfStackReserve, sizeof(ULONGLONG));
    }

    ULONGLONG PEFile::sizeOfStackCommit(){
        return this->getOptHeaderAttr(OptHeaderAttr::sizeOfStackCommit, sizeof(ULONGLONG));
    }

    ULONGLONG PEFile::sizeOfHeapReserve(){
        return this->getOptHeaderAttr(OptHeaderAttr::sizeOfHeapReserve, sizeof(ULONGLONG));
    }

    ULONGLONG PEFile::sizeOfHeapCommit(){
        return this->getOptHeaderAttr(OptHeaderAttr::sizeOfHeapCommit, sizeof(ULONGLONG));
    }

    DWORD PEFile::loaderFlags(){
        return static_cast<DWORD>(this->getOptHeaderAttr(OptHeaderAttr::loaderFlags, sizeof(DWORD)));
    }

    DWORD PEFile::numberOfRvaAndSizes(){
        return static_cast<DWORD>(this->getOptHeaderAttr(OptHeaderAttr::numberOfRvaAndSizes, sizeof(DWORD)));
    }
};