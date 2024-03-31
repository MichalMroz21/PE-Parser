#ifndef PE_CONVERTER_HPP
#define PE_CONVERTER_HPP

#include <windows.h>
#include <winnt.h>
#include <string>
#include <iostream>
#include <limits>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/dynamic_bitset.hpp>

//Simple class for interpreting the bytes in PE into human-readable data.
namespace PE_CONVERTER{
    class Converter{
    public:
        Converter();

        std::string getMachineStr(WORD machine),
                    getTimestampStr(DWORD timestamp),
                    getMagicValue(WORD magic),
                    getSubsystem(WORD subsystem);

        std::vector<std::string> getCharacteristics(WORD charasteristics),
                                 getDllCharacteristics(WORD dllCharasteristics);
    };
};
#endif
