#include "DllConverter.h"

DllConverter::DllConverter(/* args */)
{
}

DllConverter::~DllConverter()
{
}

void DllConverter::convert(std::string& dllPath, Target outputType)
{
    switch (outputType)
    {
    case Target::AXE:
        /* code */
        break;

    case Target::PIC:
        /* code */
        break;
    
    default:
        break;
    }
}