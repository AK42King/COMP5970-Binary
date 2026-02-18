import sys
import os
import pefile 
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
# Determines whether to use 32 or 64-bit disassembly based on PE header or user input
class Recursive_Descent_Disassembler:
    # Constructor(just holds) intializes the disassembler and sets up the initial state
    def __init__(self, binary_code, mode):
        self.held = binary_code
        self.pointer = 0  # starting address
        self.visited = set()
        self.stack = []
        self.edges = []
        #currenltly hardcoded to allow for 32 or 64 bit mode if user input is given
        if mode == 64:
            self.mode = CS_MODE_64
        elif mode == 32:
            self.mode = CS_MODE_32
        else:
            raise ValueError("Incompatable mode. Choose 32 or 64")
        self.disassembler = Cs(CS_ARCH_X86, self.mode)  # Initialize Capstone with the chosen mode

    # Writes CFG edges in DOT format for Graphviz visualization
    def output_cfg(self, filename="cfg.dot"):
        with open(filename, 'w') as f:
            f.write("digraph CFG {\n")
            for from_addr, to_addr in self.edges:
                f.write(f'  "{from_addr:#x}" -> "{to_addr:#x}";\n')
            f.write("}\n")

    def parse_instruction(self, start_address):
        
        if start_address is None:
            start_address = self.pointer
        
        self.stack.append(start_address)

        while self.stack:
            address = self.stack.pop()

            #skips the address if it has already been visited or is out of bounds
            if address in self.visited or address >= len(self.held):
                continue

            self.visited.add(address)

            # Disassemble the instruction at the current address
            for instruction in self.disassembler.disasm(self.held[address:], address):
                print(f"{instruction.address:#018x}: {instruction.mnemonic} {instruction.op_str}")

                next_address = instruction.address + instruction.size
            
                if instruction.mnemonic.startswith("j") or instruction.mnemonic == "call":
                    target = self.get_target_address(instruction)
                    if target is not None:
                        self.edges.append((instruction.address, target))  # Record control edge
                        if target not in self.visited:
                            self.stack.append(target)

                    #if call then continue to the next instruction
                    if instruction.mnemonic == "call":
                        self.edges.append((instruction.address, next_address))
                        self.stack.append(next_address)
                else:
                    self.edges.append((instruction.address, next_address))
                    self.stack.append(next_address)

                if instruction.mnemonic in ["ret", "jmp", "int3"]:
                    break
    # Extract target address for calls/jumps       
    def get_target_address(self, instruction):    
        try:
            if instruction.op_str.startswith("0x"):
                return int(instruction.op_str, 16)
            else:
                 # Indirect calls/jumps like jmp eax — skip for now
                return None
        except ValueError:
            return None
        
def get_pe_header(file_path):
        pe = pefile.PE(file_path)
        if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe, 'get_offset_from_rva'):
            entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_offset = pe.get_offset_from_rva(entry_rva)
            return entry_offset, (32 if pe.OPTIONAL_HEADER.Magic == 0x10b else 64)
        else:
            raise ValueError("Not a valid PE file")

def main():
    # Entry point of the program
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <path_to_file> [32|64]")
        sys.exit(1)
    mode_for_file = None
    path_to_file = sys.argv[1]
    if len(sys.argv) == 3:
        mode_for_file = int(sys.argv[2])

    if not os.path.isfile(path_to_file):
        print(f"Error: The file {path_to_file} does not exist.")
        sys.exit(1)

    #where the file is read as a binary file
    with open(path_to_file, 'rb') as f:
        binary_file_content = f.read()
    if mode_for_file is None:
        try:
            entry_offset, mode = get_pe_header(path_to_file)
        except Exception as e:
            print(f"Error reading PE header: {e}")
            sys.exit(1)
    else:
        mode = mode_for_file
        entry_offset = 0 # Default to 0 if mode is provided
    print(f"Bytes at entry: {binary_file_content[entry_offset:entry_offset+16].hex()}")
    print(f"Starting disassembly at file offset: {entry_offset:#x}")
    disassembler = Recursive_Descent_Disassembler(binary_file_content, mode)
    disassembler.parse_instruction(start_address=entry_offset)

    print("\nControl Flow Edges:")
    for from_addr, to_addr in disassembler.edges:   
        print(f"{from_addr:#x010x} -> {to_addr:#x010x}")
    disassembler.output_cfg()
    
#this is to ensure that the main function is called when the program is run 
if __name__ == "__main__":
    main()