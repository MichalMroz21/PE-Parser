#include "PEFile.hpp"

namespace PE_DATA{
    PEFile::PEFile(){}

    void PEFile::setTypeOfPE(WORD stateOfMachine){
        if(stateOfMachine == 0x010B) is64Bit = false;
        else if(stateOfMachine == 0x020B) is64Bit = true;
        else{
            std::cerr << "Invalid or unsupported stateOfMachine!";
        }
    }

    auto& PEFile::getOptionalHeader(){
        if(this->is64Bit) return this->imageOptionalHeader64;
        else return this->imageOptionalHeader32;
    }

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
};