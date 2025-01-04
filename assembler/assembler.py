import struct

def generate_idata_section(exitprocess_rva):
    """
    Generate a minimal .idata section for resolving `ExitProcess` from `kernel32.dll`.
    """
    kernel32_name = b"kernel32.dll\x00"
    exitprocess_name = b"ExitProcess\x00"

    # RVA values
    import_name_table_rva = exitprocess_rva + 0x100  # Arbitrary offset for Import Name Table
    import_address_table_rva = exitprocess_rva + 0x200  # Arbitrary offset for Import Address Table
    dll_name_rva = exitprocess_rva + 0x300  # Arbitrary offset for DLL name
    func_name_rva = exitprocess_rva + 0x310  # Arbitrary offset for function name

    # Import Directory Table (fixed at the start of .idata)
    import_directory = struct.pack(
        "<IIIIII",
        import_name_table_rva,     # OriginalFirstThunk (Import Name Table)
        0,                         # TimeDateStamp
        0,                         # ForwarderChain
        dll_name_rva,              # Name (DLL name RVA)
        import_address_table_rva,  # FirstThunk (Import Address Table)
        0,                         # Null terminator
    )

    # Null-terminating the import directory table
    null_import_directory = b"\x00" * 20

    # Import Name Table (INT) and Import Address Table (IAT)
    int_and_iat = struct.pack("<Q", func_name_rva) + b"\x00" * 8  # Hint/Name Table entry and null terminator

    # Hint/Name Table entry for `ExitProcess`
    hint_name_entry = struct.pack("<H", 0) + exitprocess_name

    # Concatenate all pieces
    idata_section = (
        import_directory +  # Import Directory Table
        null_import_directory +  # Null-terminated
        int_and_iat +  # INT (and shared with IAT)
        kernel32_name +  # DLL name
        hint_name_entry  # Function name
    )

    # Align to 512 bytes for file alignment
    return idata_section.ljust(512, b'\x00')

def generate_pe_header(code_size, idata_rva, idata_size):
    dos_header = b'MZ' + b'\x00' * 58 
    e_lfanew = struct.pack('<I', 0x82)
    dos_stub = b"This program cannot be run in DOS mode.\r\n$" + b"\x00" * 32
    pe_signature = b"PE\x00\x00"
    
    # COFF header for 64-bit
    # <Machine=0x8664, NumberOfSections=1, TimeDateStamp=0, PointerToSymbolTable=0,
    #  NumberOfSymbols=0, SizeOfOptionalHeader=?, Characteristics=0x20>
    coff_header = struct.pack("<HHIIIHH",
                              0x8664,    # Machine (AMD64)
                              1,         # NumberOfSections
                              0, 0, 0,   # TimeDateStamp, PointerToSymbolTable, NumberOfSymbols
                              0xF0,      # SizeOfOptionalHeader (we'll fix below)
                              0x20)      # Characteristics (no relocs, etc.)

    # The correct format string for 64-bit optional header with 29 fields
    PE64_HEADER_FORMAT = (
        "<"        # little-endian
        "H"        # Magic (0x20B)
        "B"        # MajorLinkerVersion
        "B"        # MinorLinkerVersion
        "I"        # SizeOfCode
        "I"        # SizeOfInitializedData
        "I"        # SizeOfUninitializedData
        "I"        # AddressOfEntryPoint
        "I"        # BaseOfCode
        "Q"        # ImageBase
        "I"        # SectionAlignment
        "I"        # FileAlignment
        "H"        # MajorOperatingSystemVersion
        "H"        # MinorOperatingSystemVersion
        "H"        # MajorImageVersion
        "H"        # MinorImageVersion
        "H"        # MajorSubsystemVersion
        "H"        # MinorSubsystemVersion
        "I"        # Win32VersionValue
        "I"        # SizeOfImage
        "I"        # SizeOfHeaders
        "I"        # CheckSum
        "H"        # Subsystem
        "H"        # DllCharacteristics
        "Q"        # SizeOfStackReserve
        "Q"        # SizeOfStackCommit
        "Q"        # SizeOfHeapReserve
        "Q"        # SizeOfHeapCommit
        "I"        # LoaderFlags
        "I"        # NumberOfRvaAndSizes
    )

    # In a minimal example, many fields can be 0 or small
    optional_header = struct.pack(
        PE64_HEADER_FORMAT,
        0x20B,       # Magic (PE32+)
        0,           # MajorLinkerVersion
        0,           # MinorLinkerVersion
        code_size,   # SizeOfCode
        idata_size,   # SizeOfInitializedData
        0,           # SizeOfUninitializedData
        0x1000,      # AddressOfEntryPoint (RVA)
        0x1000,      # BaseOfCode (RVA)
        0x140000000, # ImageBase
        0x1000,    # SectionAlignment
        0x200,     # FileAlignment
        0, 0,      # Major/Minor OS Version
        0, 0,      # Major/Minor Image Version
        5, 2,      # Major/Minor Subsystem Version
        0,         # Win32VersionValue
        0x2000,    # SizeOfImage (just a guess for minimal example)
        0x200,     # SizeOfHeaders
        0,         # CheckSum
        3,         # Subsystem (IMAGE_SUBSYSTEM_WINDOWS_CUI = 3)
        0x0040,    # DllCharacteristics
        0x100000,  # SizeOfStackReserve
        0x1000,    # SizeOfStackCommit
        0x100000,  # SizeOfHeapReserve
        0x1000,    # SizeOfHeapCommit
        0,         # LoaderFlags
        16         # NumberOfRvaAndSizes
    )

    # Update COFF header SizeOfOptionalHeader field to match our optional header's length
    # (If you want to be rigorous, recast the first struct with the correct value.)
    size_of_opt = len(optional_header)
    # Rebuild coff_header with the correct size_of_opt
    coff_header = struct.pack("<HHIIIHH",
                              0x8664,    # Machine
                              1,         # NumberOfSections
                              0, 0, 0,   # Timestamps, etc.
                              size_of_opt,
                              0x22)

    # Minimal .text section
    section_table = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",  # name
        code_size,            # virtual size
        0x1000,               # virtual address
        code_size,            # size of raw data
        0x400,                # pointer to raw data
        0,                    # pointer to relocations
        0,                    # pointer to line numbers
        0,                    # number of relocations
        0,                    # number of line numbers
        0x60000020            # characteristics
    )

    # .idata section
    idata_section = struct.pack(
        "<8sIIIIIIHHI",
        b".idata\x00\x00",     # name
        idata_size,           # virtual size
        idata_rva,            # virtual address
        idata_size,           # size of raw data
        0x600,                # pointer to raw data
        0,                    # pointer to relocations
        0,                    # pointer to line numbers
        0,                    # number of relocations
        0,                    # number of line numbers
        0xC0300040            # characteristics (initialized data, readable, writable)
    )
    return (
            dos_header +
            e_lfanew +
            dos_stub +
            pe_signature +
            coff_header +
            optional_header +
            section_table +
            idata_section
            )


def assemble_code():
    # Example 64-bit machine code for: 2 + (4 * 3) - 6
    code = bytearray()
    code += b'\xB8\x04\x00\x00\x00'  # mov  eax, 4
    code += b'\x48\x6b\xC0\x03'      # imul rax, 3
    code += b'\x48\x83\xC0\x02'      # add  rax, 2
    code += b'\x48\x83\xE8\x06'      # sub  rax, 6
    code += b'\xC3'                  # ret
    return code


def write_exe(filename, code):
    idata_rva = 0x2000
    idata_section = generate_idata_section(idata_rva)
    pe_header = generate_pe_header(len(code), idata_rva, len(idata_section))

    with open(filename, 'wb') as f:
        # Headers aligned to 512 bytes
        f.write(pe_header.ljust(512, b'\x00'))
        # Write the code section
        f.write(code.ljust(512, b'\x00'))
        f.write(idata_section)

# Assemble and write the executable
code = assemble_code()
write_exe("program.exe", code)

