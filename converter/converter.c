/* pseudo-code */
////////////////////////////////////////////////////////////////////////////////////////////
function buildAXE(pe_path, axe_path):
    pe = read_file(pe_path)

    dos = parse_dos_header(pe)
    nt  = parse_nt_headers(pe)
    sections = parse_section_headers(pe)

    axe = new AXE_Module()

////////////////////////////////////////////////////////////////////////////////////////////

for sec in sections:
    if sec.name in [".text", ".data", ".rdata", ".pdata", ".tls"]:
        raw_data = pe.read(sec.raw_offset, sec.raw_size)
        axe.add_section(sec.virtual_address, sec.virtual_size, raw_data)

////////////////////////////////////////////////////////////////////////////////////////////
    
imports = parse_import_table(pe)
for (dll_name, func_name, thunk_rva) in imports:
    hashed = hash(func_name)        // Athena uses Adler32 (dword)
    axe.imports.append({ thunk_rva, hashed })

////////////////////////////////////////////////////////////////////////////////////////////

relocs = parse_base_relocation_table(pe)
for block in relocs:
    axe.relocs.append(block)

////////////////////////////////////////////////////////////////////////////////////////////

axe.header = {
    magic: "AXE0",
    version: 1,
    entry_point_rva: nt.OptionalHeader.AddressOfEntryPoint,
    section_count: axe.sections.length,
    import_offset: calculate_offset(axe.imports),
    reloc_offset: calculate_offset(axe.relocs),
    flags: 0
}

////////////////////////////////////////////////////////////////////////////////////////////

for sec in axe.sections:
    sec.data = compress(sec.data)

////////////////////////////////////////////////////////////////////////////////////////////
    
sec.data = aes_encrypt(sec.data, random_key)
axe.header.flags |= FLAG_ENCRYPTED

////////////////////////////////////////////////////////////////////////////////////////////

outfile = open(axe_path, "wb")

write(outfile, axe.header)
write(outfile, axe.section_descriptors)

for sec in axe.sections:
    write(outfile, sec.data)

write(outfile, axe.imports)
write(outfile, axe.relocs)

close(outfile)
////////////////////////////////////////////////////////////////////////////////////////////
