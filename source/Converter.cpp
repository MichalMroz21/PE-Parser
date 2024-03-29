#include <Converter.hpp>

namespace PE_CONVERTER{

    Converter& Converter::getConverter(){
        static Converter converter;
        return converter;
    }

};