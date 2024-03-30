#include <windows.h>
#include <winnt.h>
#include <string>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/dynamic_bitset.hpp>
#include <boost/range/algorithm/copy_if.hpp>

namespace PE_CONVERTER{
    class Converter{
    public:
        Converter();

        std::string getMachineStr(WORD machine);
        std::string getTimestampStr(DWORD timestamp);
    };
};

