# Recover string names from large string blobs in Go binaries.
# @author aidanfora | Malware Analysis Intern @ CSIT
# @category Go Decompilation Scripts

from ghidra.program.model.lang import OperandType

'''
Format:
LEA RAX, [Address]
MOV EBX, (length)
Works for dynamic strings
'''
def find_strings_dynamic():
    for block in getMemoryBlocks():
        block_name = block.getName()

        if block_name not in ['.text', '__text']:
            continue

        instruction = getInstructionAt(block.getStart())

        while instruction == None:
            instruction = getInstructionAfter(instruction)

        while instruction:
            '''
            First Check: LEA RAX, [Address]
            1. The first index should be the RAX register
            2. The second index should be a memory address
            3. The instruction's mnemonic should be LEA
            '''
            register = instruction.getRegister(0)
            operand_type = instruction.getOperandType(1)
            mnemonic = instruction.getMnemonicString()

            if register is None or OperandType.isAddress(operand_type) is False or mnemonic != 'LEA':
                instruction = getInstructionAfter(instruction)
                continue
            
            instruction_two = getInstructionAfter(instruction)
            '''
            Second Check: MOV EBX, (length)
            1. The first index should be the EBX register
            2. The second index should be a hexadecimal value
            3. The instruction's mnemonic should be MOV
            '''
            register = instruction_two.getRegister(0)
            operand_type = instruction_two.getOperandType(1)
            mnemonic = instruction_two.getMnemonicString()

            if register is None or OperandType.isScalar(operand_type) is False or mnemonic != 'MOV':
                instruction = getInstructionAfter(instruction)
                continue
            '''
            Heuristic Passed! Most likely some form of dynamically allocated string
            '''
            address = instruction.getPrimaryReference(1).getToAddress()
            length = instruction_two.getOpObjects(1)[0].getValue()          # Position 1 refers to Scalar

            try:
                ascii_string = createAsciiString(address, length)
                print 'String Created: %s' % ascii_string

            except:
                instruction = getInstructionAfter(instruction)
                continue

            instruction = getInstructionAfter(instruction)

'''
Format:
LEA RDX/RSI/R8, [Pointer_Address]
MOV qword ptr [Stack Position], RDX/RSI/R8
Works for static strings
'''
def find_strings_static():
    for block in getMemoryBlocks():
        block_name = block.getName()

        if block_name not in ['.text', '__text']:
            continue

        instruction = getInstructionAt(block.getStart())

        while instruction == None:
            instruction = getInstructionAfter(instruction)

        while instruction:
            '''
            First Check: LEA RAX, [Pointer_Address]
            1. The first index should be the RSI/R8 register
            2. The second index should be a pointer to some memory address
            3. The instruction's mnemonic should be LEA
            '''
            register = instruction.getRegister(0)
            reference_check = instruction.getPrimaryReference(1)
            if reference_check != None:
                is_ptr = getDataAt(reference_check.getToAddress())
            else:
                instruction = getInstructionAfter(instruction)
                continue
            mnemonic = instruction.getMnemonicString()

            if register is None or is_ptr == None or is_ptr.isPointer() == False or mnemonic != 'LEA':
                instruction = getInstructionAfter(instruction)
                continue
            
            instruction_two = getInstructionAfter(instruction)
            original_register = register
            '''
            Second Check: MOV qword ptr [Stack Position], RSI/R8
            1. The first index should be the memory address with reference to RSP
            2. The second index should be the RSI/R8 register (must be same as the original register that LEA was used on!)
            3. The instruction's mnemonic should be MOV
            '''
            register = instruction_two.getRegister(1)
            is_rsp = instruction_two.getOpObjects(0)
            mnemonic = instruction_two.getMnemonicString()
            if register is None or register.getName() != original_register.getName() or is_rsp == [] or is_rsp[0].toString() != 'RSP' or mnemonic != 'MOV':
                instruction = getInstructionAfter(instruction)
                continue
            '''
            Heuristic Passed! Most likely some form of statically allocated string
            '''
            pointed_address = instruction.getPrimaryReference(1).getToAddress()
            address = getDataAt(pointed_address).getValue()
            length_address = pointed_address.add(8)
            length = getByte(length_address)

            try:
                ascii_string = createAsciiString(address, length)
                print 'String Created: %s' % ascii_string

            except:
                instruction = getInstructionAfter(instruction)
                continue

            instruction = getInstructionAfter(instruction)

find_strings_dynamic()
find_strings_static()
print('Strings Renamed!')