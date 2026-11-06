#include "AxeArchive.h"

#include <exception>
#include <iostream>
#include <string>

namespace
{
    void printHelp(std::ostream &out)
    {
        out << "AXE analysis archive extractor\n\n"
               "Usage: axe_extract input.axe output.dll\n"
               "       axe_extract -h | --help\n\n"
               "Validates an analysis archive and writes the original DLL bytes to disk.\n"
               "The output must not already exist. No contents are loaded or executed.\n"
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
            return 0;
        }

        if (argc != 3)
        {
            printHelp(std::cerr);
            return 2;
        }

        axe_archive::extract(argv[1], argv[2]);
        std::cout << "Extracted original DLL bytes to " << argv[2] << '\n';
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
