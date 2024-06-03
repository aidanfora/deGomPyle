# Recover string names from large string blobs in Go binaries.
# @author aidanfora | Malware Analysis Intern @ CSIT
# @category Go Decompilation Scripts


from ghidra.program.model.lang import OperandType



def rename_string():
    for block in getMemoryBlocks():
        if block.getName() != ".text":
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
            Heuristic Passed! Most likely some form of string
            '''
            address = instruction.getPrimaryReference(1).getToAddress()
            length = instruction_two.getOpObjects(1)[0].getValue()          # Position 1 refers to Scalar

            try:
                createAsciiString(address, length)

            except:
                instruction = getInstructionAfter(instruction)
                continue

            instruction = getInstructionAfter(instruction)
            
    print("Strings Renamed!")

rename_string()