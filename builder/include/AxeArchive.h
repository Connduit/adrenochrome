#ifndef ADRENOCHROME_AXE_ARCHIVE_H
#define ADRENOCHROME_AXE_ARCHIVE_H

#include <filesystem>
#include <iosfwd>

// Analysis archive only. Deliberately separate from the experimental runtime AXE structs.
namespace axe_archive
{
    void write(const std::filesystem::path &input, const std::filesystem::path &output);
    void inspect(const std::filesystem::path &archive, std::ostream &out);
    void extract(const std::filesystem::path &archive, const std::filesystem::path &output);
} // namespace axe_archive
#endif
