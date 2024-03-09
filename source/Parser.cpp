#include "Parser.hpp"

#include <boost/filesystem/operations.hpp>

Parser::Parser() {
	this->isBigEndian = isBigEndianCheck();
}

PEFile* Parser::loadPEFileFromBinary(const std::vector<BYTE>& PEBinary) {

	PE_STRUCTURE::DosHeader dosHeader{};

	if (PEBinary.size() < sizeof(PE_STRUCTURE::DosHeader)) {
		throw std::runtime_error("Invalid size of binary to read DOS_HEADER");
	}

	std::memcpy(&dosHeader, PEBinary.data(), sizeof(PE_STRUCTURE::DosHeader));

	DWORD NTHeaderLoc = dosHeader.e_lfanew;



	return nullptr;
}

PEFile* Parser::loadPEFileFromPath(const char* fullPEPath) {
	
	std::ifstream peFile(fullPEPath, std::ios::binary);

	if (!peFile.is_open()) {
		throw std::runtime_error("Error opening PE file: " + std::string(fullPEPath));
	}

	this->buffer = std::vector<BYTE>((std::istreambuf_iterator<char>(peFile)), std::istreambuf_iterator<char>());

	return this->loadPEFileFromBinary(this->buffer);
}

bool Parser::isBigEndianCheck(void) {
	union {
		uint32_t i;
		char c[4];
	} bint = { 0x01020304 };

	return bint.c[0] == 1;
}