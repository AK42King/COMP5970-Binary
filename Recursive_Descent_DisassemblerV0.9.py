import sys
import os
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
#this one still needs to have the 32 and 64 bit mode and not just hardcoded such as being able to read it from the file
class Recursive_Descent_Disassembler:
    # Constructor(just holds)
    def __init__(self, binary_code, mode):
        self.held = binary_code
        #when I need to go recursion need to make variable to hold the pointer
        self.pointer = 0
        if mode == 64:
            self.mode = CS_MODE_64
        elif mode == 32:
            self.mode = CS_MODE_32
        else:
            raise ValueError("Incompatable mode. Choose 32 or 64")
        self.disassembler = Cs(CS_ARCH_X86, self.mode)  # Initialize Capstone with the chosen mode

    def parse_instruction(self):
        #while pointer is less than total(len) of the binary code
        while self.pointer < len(self.held):
            instruction_byte = self.held[self.pointer:self.pointer + 16] #16 bytes
            for instruction in self.disassembler.disasm(self.held, self.pointer):
                yield f"{instruction.address:#x}: {instruction.mnemonic} {instruction.op_str}"
                self.pointer += instruction.size #adjusts pointer properly

def main():
    """
    Reads the (binary) file, initializes the disassembler, and prints each disassembled instruction.
    """
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_file>")
        sys.exit(1)

    path_to_file = sys.argv[1]

    try:
        if not os.path.isfile(path_to_file):
            print(f"Error: The file {path_to_file} does not exist.")
            sys.exit(1)
    except Exception as e:
        print(f"Error checking if file exists: {e}")
        sys.exit(1)

    with open(path_to_file, 'rb') as f:
        file_content = f.read()
    
    mode = 64

    disassembler = Recursive_Descent_Disassembler(file_content, mode)

    # Loop through the instructions and print them
    for instruction in disassembler.parse_instruction():
        print(instruction)

if __name__ == "__main__":
    main()