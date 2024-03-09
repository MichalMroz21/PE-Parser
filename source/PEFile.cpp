#include "PEFile.hpp"

PEFile::PEFile(PE_STRUCTURE::DosHeader dosHeader, PE_STRUCTURE::ImageNtHeaders64 imageNTHeaders64) {
	this->dosHeader = dosHeader;
	this->imageNTHeaders64 = imageNTHeaders64;
	this->is64Bit = true;
}

PEFile::PEFile(PE_STRUCTURE::DosHeader dosHeader, PE_STRUCTURE::ImageNtHeaders imageNTHeaders) {
	this->dosHeader = dosHeader;
	this->imageNTHeaders = imageNTHeaders;
}