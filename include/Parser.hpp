#ifndef PARSER
#define PARSER

#include <vector>
#include <stdint.h>
#include <windows.h>
#include <fstream>
#include <iostream>
#include <cstring>

#include "PEFile.hpp"
#include "Structure.hpp"

class Parser {
public:

	Parser();

	[[nodiscard]]
	PEFile* loadPEFileFromPath(const char* fullPEPath);

	[[nodiscard]]
	PEFile* loadPEFileFromBinary(const std::vector<BYTE>& PEBinary);
	
private:

	bool isBigEndianCheck(void);
    
	bool isBigEndian{};
	std::vector<BYTE> buffer{};
};

#endif