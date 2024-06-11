# Recover dynamically allocated string names from large string blobs in Go binaries.
# @author aidanfora | Malware Analysis Intern @ CSIT
# @category Go Decompilation Scripts

from ghidra.program.model.lang import OperandType

'''
Format for Go >= 1.18:
LEA RAX, [Address]
MOV EBX, (length)
'''
def find_dynamic_strings_118():
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
Format for Go 1.16-1.17:
LEA RAX, [Address]
MOV qword ptr [Stack Position], RAX
MOV qword ptr [Stack Position], (length)
'''
def find_dynamic_strings_116():
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
            1. The first index should be the RAX register (or some register)
            2. The second index should be a memory address
            3. The instruction's mnemonic should be LEA
            '''
            register = instruction.getRegister(0)
            operand_type = instruction.getOperandType(1)
            mnemonic = instruction.getMnemonicString()

            if (register is None or 
                OperandType.isAddress(operand_type) is False or 
                mnemonic != 'LEA'):
                instruction = getInstructionAfter(instruction)
                continue
            
            instruction_two = getInstructionAfter(instruction)
            original_register = register

            '''
            Second Check: MOV qword ptr [Stack Position], RSI/R8
            1. The first index should be the memory address with reference to RSP/ESP
            2. The second index should be the RSI/R8 register (must be same as the original register that LEA was used on!)
            3. The instruction's mnemonic should be MOV
            '''
            register = instruction_two.getRegister(1)
            is_rsp = instruction_two.getOpObjects(0)
            mnemonic = instruction_two.getMnemonicString()

            if (len(is_rsp) == 0 or is_rsp[0].toString() not in ['RSP', 'ESP'] or 
                register is None or register.getName() != original_register.getName() or 
                mnemonic != 'MOV'):
                instruction = getInstructionAfter(instruction)
                continue

            instruction_three = getInstructionAfter(instruction_two)

            '''
            Third Check: MOV qword ptr [Stack Position], (length))
            1. The first index should be the memory address with reference to RSP/ESP
            2. The second index should be scalar-valued length
            3. The instruction's mnemonic should be MOV
            '''
            operand_type = instruction_three.getOperandType(1)
            is_rsp = instruction_three.getOpObjects(0)
            mnemonic = instruction_three.getMnemonicString()

            if OperandType.isScalar(operand_type) is False or is_rsp == [] or is_rsp[0].toString() not in ['RSP', 'ESP'] or mnemonic != 'MOV':
                instruction = getInstructionAfter(instruction)
                continue

            # Heuristic Passed! Most likely some form of dynamically allocated string
            address = instruction.getPrimaryReference(1).getToAddress()
            length = instruction_three.getOpObjects(1)[0].getValue()          

            try:
                ascii_string = createAsciiString(address, length)
                print 'String Created: %s' % ascii_string

            except:
                instruction = getInstructionAfter(instruction)
                continue

            instruction = getInstructionAfter(instruction)

find_dynamic_strings_118()
find_dynamic_strings_116()
print('Dynamic Strings Renamed!')