# Recover function names in stripped Go binaries.
# @author aidanfora | Malware Analysis Intern @ CSIT
# @category Go Decompilation Scripts

from ghidra.program.model.symbol.SourceType import *

PCLNTAB_MAGIC = [
    '\xfb\xff\xff\xff\x00\x00',
    '\xfa\xff\xff\xff\x00\x00',
    '\xf1\xff\xff\xff\x00\x00',
    '\xf0\xff\xff\xff\x00\x00'
]

# Find gopclntab structure in Windows PE files
def find_gopclntab_pe():
    for magic in PCLNTAB_MAGIC:
        pclntab = currentProgram.getMinAddress()
        while pclntab is not None:
            pclntab = findBytes(pclntab.add(1), magic)
            if pclntab and is_pclntab(pclntab):
                print 'gopclntab found! Start Address: %s'
                return pclntab
    return None

# Test if gopclntab was found by checking pc quantum and pointer size values
def is_pclntab(address):
    pc_quantum = getByte(address.add(6))
    pointer_size = getByte(address.add(7))
    return pc_quantum in [1, 2, 4] and pointer_size in [4, 8]

# Find the gopclntab section in Linux ELF files and MacOS Mach-O files
def find_gopclntab():
    for block in getMemoryBlocks():
        if block.getName() == '.gopclntab' or block.getName() == '__gopclntab':
            start_address = block.getStart()
            end_address = block.getEnd()
            print '%s: [Start Address: 0x%x | End Address: 0x%x]' % (block.getName(), start_address.getOffset(), end_address.getOffset())
            return start_address
    print 'No gopclntab found.'
    return None

# Recover function names based on Go version number
def rename_func(start, version):
    '''
    For reference, the PC Header Structure is as such:
    // pcHeader holds data used by the pclntab lookups.
    type pcHeader struct {
        magic          uint32  // 0xFFFFFFF1
        pad1, pad2     uint8   // 0,0
        minLC          uint8   // min instruction size
        ptrSize        uint8   // size of a ptr in bytes
        nfunc          int     // number of functions in the module
        nfiles         uint    // number of entries in the file tab
        textStart      uintptr // base for function entry PC offsets in this module
        funcnameOffset uintptr // offset to the funcnametab variable from pcHeader
        cuOffset       uintptr // offset to the cutab variable from pcHeader
        filetabOffset  uintptr // offset to the filetab variable from pcHeader
        pctabOffset    uintptr // offset to the pctab variable from pcHeader
        pclnOffset     uintptr // offset to the pclntab variable from pcHeader
    }
    
    Some clarifications to the naming conventions:
        funcnametab: holds the starting address pointed to by the funcnameOffset (which contains the strings of function names)
        pclntab: holds the starting memory address pointed to by the pclnOffset (which contains pointers to the actual functions)
    '''
    ptrsize = getByte(start.add(7))
    
    if version == '1.2':
        if ptrsize == 8:
            npclntab = getLong(start.add(8))
        else:
            npclntab = getInt(start.add(8))
        pclntab = start.add(8 + ptrsize)

    elif version == '1.16':
        if ptrsize == 8:
            npclntab = getLong(start.add(8))
            offset = getLong(start.add(8 + 2*ptrsize))
            funcnametab = start.add(offset)
            offset = getLong(start.add(8 + 6*ptrsize))
        else:
            npclntab = getInt(start.add(8))
            offset = getInt(start.add(8 + 2*ptrsize))
            funcnametab = start.add(offset)
            offset = getInt(start.add(8 + 6*ptrsize))
        pclntab = start.add(offset)

    elif version == '1.18':
        if ptrsize == 8:
            npclntab = getLong(start.add(8))
            textStart = getLong(start.add(8 + 2*ptrsize))
            offset = getLong(start.add(8 + 3*ptrsize))
            funcnametab = start.add(offset)
            offset = getLong(start.add(8 + 7*ptrsize))
        else:
            npclntab = getInt(start.add(8))
            textStart = getInt(start.add(8 + 2*ptrsize))
            offset = getInt(start.add(8 + 3*ptrsize))
            funcnametab = start.add(offset)
            offset = getInt(start.add(8 + 7*ptrsize))
        pclntab = start.add(offset)
        pclntabFieldSize = 4
    
    p = pclntab
    for i in range(npclntab):
        if version == '1.2' or version == '1.16':
            if ptrsize == 8:
                func_address = currentProgram.getAddressFactory().getAddress(hex(getLong(p)).rstrip("L"))
                p = p.add(ptrsize)
                data_offset = getLong(p)
            else:
                func_address = currentProgram.getAddressFactory().getAddress(hex(getInt(p)))
                p = p.add(ptrsize)
                data_offset = getInt(p)
            p = p.add(ptrsize)
            name_pointer = start.add(data_offset + ptrsize)
            name_address = start.add(getInt(name_pointer))
        else:  # version == '1.18'
            func_address = currentProgram.getAddressFactory().getAddress(hex(getInt(p) + textStart).rstrip("L"))
            p = p.add(pclntabFieldSize)
            data_offset = getInt(p)
            p = p.add(pclntabFieldSize)
            name_pointer = pclntab.add(data_offset + pclntabFieldSize)
            name_address = funcnametab.add(getInt(name_pointer))
        
        func_name = getDataAt(name_address)

        # Attempt to define function name
        if func_name is None:
            try:
                func_name = createAsciiString(name_address)
            except:
                print('Error: No name')
                continue
        
        func = getFunctionAt(func_address)
        if func is not None:
            func_name_old = func.getName()
            func.setName(func_name.getValue().replace(" ", ""), USER_DEFINED)
            print 'Function %s renamed as %s' % (func_name_old, func_name.getValue())
        else:
            func = createFunction(func_address, func_name.getValue())
            print 'New function created: %s' % func_name


def main():
    executable_format = currentProgram.getExecutableFormat()
    start = None
    
    if executable_format in ['Portable Executable (PE)', 'Mac OS X Mach-O', 'Executable and Linking Format (ELF)']:
        print '%s file found, trying to find gopclntab...' % executable_format
        if executable_format == 'Portable Executable (PE)':
            start = find_gopclntab_pe()
        else:
            start = find_gopclntab()
    else:
        print 'Incorrect file format.'

    if start is not None:
        magic = getInt(start) & 0xffffffff
        if magic in [0xfffffff0, 0xfffffff1]:
            rename_func(start, '1.18')
        elif magic == 0xfffffffa:
            rename_func(start, '1.16')
        elif magic == 0xfffffffb:
            rename_func(start, '1.2')
        else:
            print 'Go Version could not be determined, assuming Go 1.18 compatibility'
            rename_func(start, '1.18')

main()