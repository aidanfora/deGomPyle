# Recover statically allocated string names from large string blobs in Go binaries.
# @author aidanfora | Malware Analysis Intern @ CSIT
# @category Go Decompilation Scripts

from ghidra.program.model.data import PointerDataType, IntegerDataType
from ghidra.program.model.data import LongDataType

# Get image base and maximum offset of the current program.
image_base = currentProgram.getImageBase()
max_offset = currentProgram.getMaxAddress()
pointer_size = currentProgram.getDefaultPointerSize()
print 'Pointer Size: %d' % pointer_size

# Check if a string contains only printable characters.
def is_printable(s, length):
    for _ in range(length):
        if getByte(s) not in range(32, 126):
            return False
        s = s.add(1)
    return True

# Get the length of the string from the address based on pointer size.
def get_string_length(length_address):
    if pointer_size == 8:
        return getLong(length_address)
    else:
        return getInt(length_address)

# Get the address of the string from the pointer.
def get_string_address(string_address_pointer):
    if pointer_size == 8:
        return currentProgram.getAddressFactory().getAddress(hex(getLong(string_address_pointer)).rstrip("L"))
    else:
        return currentProgram.getAddressFactory().getAddress(hex(getInt(string_address_pointer)))

# Process each memory block to find and rename strings.
def process_memory_block(block, pointer_size):
    name = block.getName()
    start = block.getStart()
    end = block.getEnd()
    print '%s found! Start Address: 0x%s | End Address: 0x%s' % (name, start.toString(), end.toString())
    while start <= end:
        string_address_pointer = start
        length_address = start.add(pointer_size)
        start = start.add(pointer_size)
        try:
            length = get_string_length(length_address)
            string_address = get_string_address(string_address_pointer)
            '''
            3 Checks:
            1. String must not be absurdly long (> 100 characters)
            2. String must not exist outside of the binary's current process memory
            3. String must be made of printable ASCII Characters
            '''
            if (length not in range(1, 100) or
                string_address < image_base or string_address >= max_offset or
                not is_printable(string_address, length)):
                continue

            createData(string_address_pointer, PointerDataType.dataType)

            existing_data = getDataAt(length_address)
            if existing_data is not None:
                data_type = existing_data.getDataType()
                if data_type.getName() in ["undefined4", "undefined8"]: # Undefined data must be removed to create integers
                    removeData(existing_data)

            createData(length_address, IntegerDataType.dataType)    # Create length
            new_string = createAsciiString(string_address, length)  # Create string
            print 'String Created: %s' % new_string
        except:
            continue

def find_static_strings():
    for block in getMemoryBlocks():
        if block.getName() in [".data", ".rodata", ".rdata"]:
            process_memory_block(block, pointer_size)

find_static_strings()
