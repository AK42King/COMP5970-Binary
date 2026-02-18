import sys
import os
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
#currently hardcoded to allow for both 32 or 64 but need to specify for the 32 bit since 64 is default
class Recursive_Descent_Disassembler:
    # Constructor(just holds)
    def __init__(self, binary_code, mode):
        self.held = binary_code
        #this is what allows for the recursion to work since it is the counter for place in the held code for disassembly 
        self.pointer = 0
        #currenltly hardcoded to allow for 32 or 64 bit mode
        if mode == 64:
            self.mode = CS_MODE_64
        elif mode == 32:
            self.mode = CS_MODE_32
        else:
            raise ValueError("Incompatable mode. Choose 32 or 64")
        self.disassembler = Cs(CS_ARCH_X86, self.mode)  # Initialize Capstone with the chosen mode

    def parse_instruction(self):
        #while pointer is less than total(len) of the binary code currently does all or nothing
        while self.pointer < len(self.held):
            for instruction in self.disassembler.disasm(self.held, self.pointer):
                yield f"{instruction.address:#x}: {instruction.mnemonic} {instruction.op_str}"
                self.pointer += instruction.size #adjusts pointer properly

def main():
    """
    Reads the (binary) file, initializes the disassembler, and prints each disassembled instruction.
    """
    if len(sys.argv) != (2 or 3):
        print(f"Usage: {sys.argv[0]} <path_to_file>")
        sys.exit(1)
    mode_for_file = None
    path_to_file = sys.argv[1]
    if len(sys.argv) >= 3:
        mode_for_file = int(sys.argv[2])
    try:
        if not os.path.isfile(path_to_file):
            print(f"Error: The file {path_to_file} does not exist.")
            sys.exit(1)
    except Exception as e:
        print(f"Error checking if file exists: {e}")
        sys.exit(1)
    #where the file is read as a binary file
    with open(path_to_file, 'rb') as f:
        binary_file_content = f.read()

    if mode_for_file is None:
        mode = 64
    else:
        mode = mode_for_file

    disassembler = Recursive_Descent_Disassembler(binary_file_content, mode)

    # Loop through the instructions and prints them
    for instruction in disassembler.parse_instruction():
        print(instruction)
#this is to ensure that the main function is called when the program is run 
if __name__ == "__main__":
    main()