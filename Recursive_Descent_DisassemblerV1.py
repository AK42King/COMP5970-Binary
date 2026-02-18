import sys
import os
import pefile 
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
# Determines whether to use 32 or 64-bit disassembly based on PE header or user input
class Recursive_Descent_Disassembler:
    # Constructor(just holds) intializes the disassembler and sets up the initial state
    def __init__(self, binary_code, mode, base_address, pe):
        self.held = binary_code
        self.pointer = 0  # starting address
        self.visited = {}
        self.stack = []
        self.edges = []
        self.base_address = base_address
        self.pe = pe
        self.junk_address = set()
        #currenltly hardcoded to allow for 32 or 64 bit mode if user input is given
        if mode == 64:
            self.mode = CS_MODE_64
        elif mode == 32:
            self.mode = CS_MODE_32
        else:
            raise ValueError("Incompatable mode. Choose 32 or 64")
        self.disassembler = Cs(CS_ARCH_X86, self.mode)  # Initialize Capstone with the chosen mode
    #gets the entry point and image base from the PE(Portable Executable(Windows))header
    def get_pe_header(file_path):
        pe = pefile.PE(file_path)
        if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe, 'get_offset_from_rva'):
            entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_offset = pe.get_offset_from_rva(entry_rva)
            image_base = pe.OPTIONAL_HEADER.ImageBase
            mode = 32 if pe.OPTIONAL_HEADER.Magic == 0x10b else 64
            return entry_offset, image_base, mode, pe
        else:
            raise ValueError("Not a valid PE file")

    def parse_instruction(self, start_address):
        
        if start_address is None:
            start_address = self.pointer
        
        self.stack.append(start_address)
        pattern_counter = 0
        while self.stack:
            address = self.stack.pop()
            max_linear = 30
            linear_count = 0
            self.visited[address] = self.visited.get(address, 0) + 1
            if self.visited[address] > 5:
                print(f"[!] Loop suspected at {hex(address)} — seen {self.visited[address]} times")
                continue
            
            if len(self.edges) > 500000:
                print("[!] Too many edges — halting disassembly.")
                return

            #the try but continue is used to skip the address if it is out of bounds
            try:
                file_offset = self.pe.get_offset_from_rva(address - self.base_address)
                if file_offset >= len(self.held):
                    continue
            except Exception:
                continue

            # Disassemble the instruction 
            for instruction in self.disassembler.disasm(self.held[file_offset:], address):
                print(f"{instruction.address:#018x}: {instruction.mnemonic} {instruction.op_str}")
                
                # Attempt to Detect junk loop (e.g. add byte ptr [rax], al spam)
                junk_mnemonics = {"add", "nop", "pop"}
                junk_op_strs = {"byte ptr", "r10"}

                if instruction.mnemonic in junk_mnemonics and any(op in instruction.op_str for op in junk_op_strs):
                    pattern_counter += 1
                    self.junk_address.add(instruction.address)
                    if pattern_counter > 10:
                        print(f"[!] Detected repeating junk at {hex(instruction.address)} — skipping further instructions here.")
                        break
                else:
                    pattern_counter = 0         

                linear_count += 1
                next_address = instruction.address + instruction.size
                if linear_count > max_linear:
                    print(f"[!] Too many linear instructions — halting disassembly at {hex(address)}")
                    break
                if instruction.mnemonic.startswith("j") or instruction.mnemonic == "call":
                    target = self.get_target_address(instruction)
                    if target is not None:
                        self.edges.append((instruction.address, target))  # Record control edge
                        if target not in self.visited and target not in self.junk_address:
                            self.stack.append(target)

                        #if call then continue to the next instruction
                        if instruction.mnemonic == "call":
                            self.edges.append((instruction.address, next_address))
                            self.stack.append(next_address)
                            if len(self.stack) > 100000:
                                print("[!] Stack overflow risk — halting recursion(in).")
                                return
                    else: #added due to indirect calls leading to loops
                        print(f"[!] Skipping indirect {instruction.mnemonic} at {instruction.address:#x} ->  {instruction.op_str}")
                        break
                else:
                    self.edges.append((instruction.address, next_address))
                    if next_address not in self.visited and next_address not in self.junk_address:
                        self.stack.append(next_address)
                        if len(self.stack) > 100000:
                            print("[!] Stack overflow risk — halting recursion.")
                            return
                    if instruction.mnemonic in ["ret", "jmp", "int3"]:
                        break
                #if the instruction is a return or jump then break out of the loop

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
        
    # Writes CFG edges in DOT format for Graphviz visualization
    def output_cfg(self, filename="cfg.dot"):
        with open(filename, 'w') as f:
            f.write("""digraph CFG {
                node [shape=box, fontname="Courier"];
                rankdir=LR;
            """)
            for from_addr, to_addr in self.edges:
                f.write(f'  "{from_addr:#x}" -> "{to_addr:#x}";\n')
            f.write("}\n")
        
def main():
    # Entry point of the program
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_file>")
        sys.exit(1)
    mode_for_file = None
    path_to_file = sys.argv[1]

    if not os.path.isfile(path_to_file):
        print(f"Error: The file {path_to_file} does not exist.")
        sys.exit(1)

    #where the file is read as a binary file
    with open(path_to_file, 'rb') as f:
        binary_file_content = f.read()
    if mode_for_file is None:
        try:
            entry_offset, image_base, mode, pe = Recursive_Descent_Disassembler.get_pe_header(path_to_file)
        except Exception as e:
            print(f"Error reading PE header: {e}")
            sys.exit(1)
    else:
        mode = mode_for_file
        entry_offset = 0 # Default to 0 if mode is provided
        pe = None #no section mapping 
    disassembler = Recursive_Descent_Disassembler(binary_file_content, mode, image_base, pe)
    disassembler.parse_instruction(start_address=entry_offset)

    '''print("\nControl Flow Edges:")
    for from_addr, to_addr in disassembler.edges:   
        print(f"{from_addr:#010x} -> {to_addr:#010x}")'''
    disassembler.output_cfg()
    
#this is to ensure that the main function is called when the program is run 
if __name__ == "__main__":
    main()