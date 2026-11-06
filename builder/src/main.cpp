#include "AxeArchive.h"

#include <exception>
#include <iostream>
#include <string>

namespace
{
    void printHelp(std::ostream &out)
    {
        out << "AXE analysis archive builder\n\n"
               "Usage:\n"
               "  builder pack input.dll output.axe\n"
               "  builder inspect input.axe\n"
               "  builder extract input.axe output.dll\n"
               "  builder -h | --help\n\n"
               "Commands:\n"
               "  pack     Validate basic PE DLL structure and archive the complete file.\n"
               "  inspect  Validate an archive and display its PE machine and sections.\n"
               "  extract  Validate an archive and restore the original DLL bytes.\n\n"
               "Output files must not already exist. DLL inputs are limited to 256 MiB.\n"
               "Archives preserve all original bytes; no identifying information is stripped.\n"
               "Analysis archives only; no code is loaded or executed.\n"
               "These archives are incompatible with the existing runtime loader.\n\n"
               "Examples:\n"
               "  builder pack engine.dll engine.axe\n"
               "  builder inspect engine.axe\n"
               "  builder extract engine.axe restored.dll\n\n"
               "Exit codes: 0 success/help, 1 file or format error, 2 invalid syntax.\n";
    }
} // namespace

int main(int argc, char *argv[])
{
    try
    {
        if (argc == 2 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help"))
        {
            printHelp(std::cout);
        }
        else if (argc == 4 && std::string(argv[1]) == "pack")
        {
            axe_archive::write(argv[2], argv[3]);
        }
        else if (argc == 3 && std::string(argv[1]) == "inspect")
        {
            axe_archive::inspect(argv[2], std::cout);
        }
        else if (argc == 4 && std::string(argv[1]) == "extract")
        {
            axe_archive::extract(argv[2], argv[3]);
        }
        else
        {
            printHelp(std::cerr);
            return 2;
        }
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
