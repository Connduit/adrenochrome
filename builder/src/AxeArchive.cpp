#include "AxeArchive.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace axe_archive {
namespace {
using Bytes = std::vector<unsigned char>;
constexpr std::uint64_t maxSize = 256ull * 1024 * 1024;
constexpr std::size_t headerSize = 32;
constexpr std::array<unsigned char, 8> magic{{'A','X','E','A','R','C','H',0}};

std::uint64_t get(const Bytes& data, std::size_t offset, unsigned width) {
    if (offset > data.size() || width > data.size() - offset)
        throw std::runtime_error("Truncated field or invalid offset");
    std::uint64_t value = 0;
    for (unsigned i = 0; i < width; ++i)
        value |= std::uint64_t(data[offset + i]) << (8 * i);
    return value;
}
void put(Bytes& data, std::uint64_t value, unsigned width) {
    for (unsigned i = 0; i < width; ++i)
        data.push_back(static_cast<unsigned char>(value >> (8 * i)));
}
std::uint32_t checksum(const Bytes& data, std::size_t begin) {
    std::uint32_t hash = 2166136261u;
    for (std::size_t i = begin; i < data.size(); ++i)
        hash = (hash ^ data[i]) * 16777619u;
    return hash;
}
Bytes read(const std::filesystem::path& path, std::uint64_t limit) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("Cannot open input file");
    const auto size = stream.tellg();
    if (size < 0 || static_cast<std::uint64_t>(size) > limit)
        throw std::runtime_error("Input exceeds size limit or size is unavailable");
    Bytes data(static_cast<std::size_t>(size));
    stream.seekg(0);
    if (!data.empty() && !stream.read(reinterpret_cast<char*>(data.data()), size))
        throw std::runtime_error("Cannot read complete input file");
    return data;
}
void save(const std::filesystem::path& path, const Bytes& data) {
    // Existing files (including symlinks) must never be overwritten.
    // This CLI assumes the output directory is not concurrently modified.
    if (std::filesystem::symlink_status(path).type() != std::filesystem::file_type::not_found)
        throw std::runtime_error("Output already exists");
    std::ofstream stream(path, std::ios::binary);
    if (!stream) throw std::runtime_error("Cannot create output file");
    stream.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    stream.close();
    if (!stream) {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        throw std::runtime_error("Failed to write complete output file");
    }
}
struct Section {
    std::string name;
    std::uint32_t offset, size;
};
struct PeInfo {
    std::uint16_t machine;
    std::vector<Section> sections;
};
PeInfo describePe(const Bytes& data) {
    if (data.size() < 64 || get(data, 0, 2) != 0x5a4d)
        throw std::runtime_error("Input is not a PE DLL (missing DOS header)");
    const auto pe = get(data, 0x3c, 4);
    if (get(data, pe, 4) != 0x4550)
        throw std::runtime_error("Invalid PE signature");
    PeInfo info{static_cast<std::uint16_t>(get(data, pe + 4, 2)), {}};
    const auto count = get(data, pe + 6, 2);
    const auto optionalSize = get(data, pe + 20, 2);
    if (!(get(data, pe + 22, 2) & 0x2000))
        throw std::runtime_error("PE file is not marked as a DLL");
    const auto optional = pe + 24;
    const auto kind = get(data, optional, 2);
    if ((kind != 0x10b && kind != 0x20b) || optionalSize < (kind == 0x20b ? 112 : 96))
        throw std::runtime_error("Invalid PE optional header");
    const auto table = optional + optionalSize;
    if (!count || count > 96 || table > data.size() || count * 40 > data.size() - table)
        throw std::runtime_error("Invalid PE section table");
    for (std::uint64_t i = 0; i < count; ++i) {
        const auto entry = table + i * 40;
        std::string name;
        for (unsigned j = 0; j < 8 && data[entry + j]; ++j) {
            const auto c = data[entry + j];
            name.push_back(c >= 32 && c <= 126 ? static_cast<char>(c) : '?');
        }
        const auto size = get(data, entry + 16, 4);
        const auto offset = get(data, entry + 20, 4);
        if (size && (offset > data.size() || size > data.size() - offset))
            throw std::runtime_error("Section exceeds input bounds");
        info.sections.push_back({name, static_cast<std::uint32_t>(offset), static_cast<std::uint32_t>(size)});
    }
    return info;
}
Bytes load(const std::filesystem::path& path) {
    auto data = read(path, maxSize + headerSize);
    if (data.size() < headerSize || !std::equal(magic.begin(), magic.end(), data.begin()))
        throw std::runtime_error("Not an AXE analysis archive");
    if (get(data, 8, 4) != 1 || get(data, 12, 4) != headerSize || get(data, 28, 4) != 0)
        throw std::runtime_error("Unsupported archive version, header size, or flags");
    if (get(data, 16, 8) != data.size() - headerSize)
        throw std::runtime_error("Archive length mismatch");
    if (get(data, 24, 4) != checksum(data, headerSize))
        throw std::runtime_error("Archive checksum mismatch");
    Bytes payload(data.begin() + headerSize, data.end());
    describePe(payload);
    return payload;
}
}
void write(const std::filesystem::path& input, const std::filesystem::path& output) {
    auto payload = read(input, maxSize);
    describePe(payload);
    Bytes archive(magic.begin(), magic.end());
    put(archive, 1, 4);
    put(archive, headerSize, 4);
    put(archive, payload.size(), 8);
    put(archive, checksum(payload, 0), 4);
    put(archive, 0, 4);
    archive.insert(archive.end(), payload.begin(), payload.end());
    save(output, archive);
}
void inspect(const std::filesystem::path& archive, std::ostream& out) {
    const auto payload = load(archive);
    const auto info = describePe(payload);
    out << "AXE analysis archive version: 1\nOriginal bytes: " << payload.size()
        << "\nPE machine: 0x" << std::hex << info.machine << std::dec
        << "\nSections: " << info.sections.size() << '\n';
    for (const auto& section : info.sections)
        out << section.name << ": offset=" << section.offset << " bytes=" << section.size << '\n';
    out << "Validation: passed (archive integrity and PE structural checks only)\n";
}
void extract(const std::filesystem::path& archive, const std::filesystem::path& output) {
    save(output, load(archive));
}
}
