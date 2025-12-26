#ifndef ADRENOCHROME_DLL_CONVERTER_H
#define ADRENOCHROME_DLL_CONVERTER_H

#include <string>
#include <cstdint>

class DllConverter
{
public:

    enum class Target : uint8_t
    {
        AXE,
        PIC
    };

    DllConverter();
    ~DllConverter();
    void convert(std::string& dllPath, Target outputType = Target::AXE);
private:
};



#endif 