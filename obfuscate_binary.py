import random
import struct
import pefile
from elftools.elf.elffile import ELFFile

# Generate random bytes
def random_bytes(length):
    return bytes(random.getrandbits(8) for _ in range(length))

# Find gopclntab section in Linux ELF files
def find_gopclntab_section_elf(file_path):
    with open(file_path, 'rb') as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if section.name == '.gopclntab' or section.name == '__gopclntab':
                print(f'gopclntab found! Start Address: 0x{section['sh_addr']}')
                return section['sh_addr'], section.data()
    print("No gopclntab found.")
    return None

# Find gopclntab structure in Windows PE files
def find_gopclntab_section_pe(file_path):
    pe = pefile.PE(file_path)
    rdata_section = next((section for section in pe.sections if section.Name.startswith(b'.rdata')), None)
    if not rdata_section:
        print("No .rdata section found.")
        return None

    rdata_data = pe.get_data(rdata_section.VirtualAddress, rdata_section.Misc_VirtualSize)
    
    magic = b'\xf1\xff\xff\xff\x00\x00'
    index = rdata_data.find(magic)
    if index != -1:
        start_address = rdata_section.VirtualAddress + index
        print(f'gopclntab found! Start Address: 0x{start_address:X}')
        return start_address

    print("No gopclntab magic bytes found.")
    return None

# Find the start address of the function name table
def get_funcnametab_address(start_address, elf=None, pe=None):
    offset = 32
    if elf is not None:
        funcnametab_offset = struct.unpack_from('<Q', elf, offset)[0]
        funcnametab_address = start_address + funcnametab_offset
    
    if pe is not None:
        funcnametab_offset = pe.get_dword_at_rva(start_address + offset)
        funcnametab_address = start_address + funcnametab_offset

    return funcnametab_address

def modify_gopclntab_elf(file_path, length_to_modify):
    start_address, gopclntab_data = find_gopclntab_section_elf(file_path)
    if not start_address or not gopclntab_data:
        print('gopclntab section not found')
        return

    funcnametab_address = get_funcnametab_address(start_address, elf=gopclntab_data)
    print(f'funcnametab found at memory address: {funcnametab_address:X}')

    with open(file_path, 'rb') as f:
        binary = f.read()

    with open(file_path, 'rb') as f:
        elf = ELFFile(f)
        for segment in elf.iter_segments():
            if segment['p_vaddr'] <= funcnametab_address < segment['p_vaddr'] + segment['p_filesz']:
                funcnametab_file_offset = funcnametab_address - segment['p_vaddr'] + segment['p_offset']
                break

    random_data = random_bytes(length_to_modify)
    modified_binary = bytearray(binary)
    modified_binary[funcnametab_file_offset:funcnametab_file_offset + length_to_modify] = random_data

    with open(file_path + '.obfuscated', 'wb') as f:
        f.write(modified_binary)

    print(f"Modified binary written to {file_path}.obfuscated")

def modify_gopclntab_pe(file_path, length_to_modify):
    pe = pefile.PE(file_path)

    start_address = find_gopclntab_section_pe(file_path)
    if not start_address:
        print('gopclntab section not found')
        return

    funcnametab_address = get_funcnametab_address(start_address, pe=pe)
    print(f'funcnametab found at memory address: 0x{funcnametab_address:X}')

    with open(file_path, 'rb') as f:
        binary = f.read()

    random_data = random_bytes(length_to_modify)
    modified_binary = bytearray(binary)
    funcnametab_file_offset = pe.get_offset_from_rva(funcnametab_address)
    modified_binary[funcnametab_file_offset:funcnametab_file_offset + length_to_modify] = random_data

    with open(file_path.rstrip('.exe') + '_obfuscated.exe', 'wb') as f:
        f.write(modified_binary)

    print(f"Modified binary written to {file_path.rstrip('.exe')}_obfuscated.exe")

# Determine the file type and modify accordingly
def modify_gopclntab(file_path, length_to_modify):
    with open(file_path, 'rb') as f:
        magic = f.read(4)
    if magic[:4] == b'\x7fELF':
        print('ELF file detected')
        modify_gopclntab_elf(file_path, length_to_modify)
    elif magic[:2] == b'MZ':
        print('PE file detected')
        modify_gopclntab_pe(file_path, length_to_modify)
    else:
        print('Unsupported file format')

modify_gopclntab('\path\to\binary', 100)