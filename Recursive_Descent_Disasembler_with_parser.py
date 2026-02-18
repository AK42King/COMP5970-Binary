import sys
import os

class Recursive_Descent_Disassembler:
    # Constructor(just holds)
    def __init__(self, binary_code):
        self.held = binary_code
        #when I need to go recursion need to make variable to hold the pointer
        self.pointer = 0
        #used it more than I thought I would
        self.reg_name = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
        self.opsize = 32  # Default operand size (in bits)
        
    def read_byte(self):
        # reads the next byte from the code and stops if it reaches the end
        if self.pointer >= len(self.held):
            return None
        byte = self.held[self.pointer]
        self.pointer += 1
        return byte

    def read_imm32(self):
        # reads the next 4-byte immediate value from the code
        imm_bytes = [self.read_byte() for _ in range(4)]
        if None in imm_bytes:  # Check if we ran out of bytes
            raise ValueError("Unexpected end of binary code while reading imm32(not enough bytes)")
        return int.from_bytes(imm_bytes, 'little')
    
    def read_rel_address(self, size):
        # reads the next size(1, 2, or 4) byte relative address from the code
        rel_bytes = [self.read_byte() for _ in range(size)]
        if None in rel_bytes:  # Check if we ran out of bytes
            raise ValueError("Unexpected end of binary code while reading rel_address(not enough bytes)")
        return int.from_bytes(rel_bytes, 'little')
    
    def get_addressing_mode(self, mod, r_m): #used when rm is used and modrm is needed
        addressing_mode = ""
        extra_bytes = 0  # Count of extra bytes needed 4 by default due to high use
        
        if mod == 0b00:  # No displacement
            if r_m == 0b110:  # [disp32]
                addressing_mode = "[disp32]"  # Needs an additional 4 bytes
                extra_bytes = 4
            elif r_m == 0b100:  #  SIB byte
                sib_byte = self.read_byte()
                if sib_byte is None:
                    raise Exception("Error: Not enough bytes for SIB")
                scale = (sib_byte >> 6) & 0b11
                index = (sib_byte >> 3) & 0b111
                base = sib_byte & 0b111

                scale_factors = [1, 2, 4, 8]
                addressing_mode = f"[{self.reg_name[base]} + {self.reg_name[index]} * {scale_factors[scale]}]"
            elif r_m == 0b101:  # [disp]
                addressing_mode = f"[{self.reg_name[r_m]}]"  # Register mode
                extra_bytes = 4
            else:
                addressing_mode = f"[{self.reg_name[r_m]}]"

        elif mod == 0b01:  # Displacement8
            addressing_mode = f"[{self.reg_name[r_m]} + disp8]"  # Needs an additional byte
            extra_bytes = 1  # one extra bytes needed

        elif mod == 0b10:  # Displacement32
            addressing_mode = f"[{self.reg_name[r_m]} + disp32]"  # Needs an additional 4 bytes
            extra_bytes = 4

        elif mod == 0b11:  # Register direct
            addressing_mode = self.reg_name[r_m]  # Register mode

        return addressing_mode, extra_bytes
    
    def read_modrm(self):
        modRM = self.read_byte()
        if modRM is None:
            return None
        mod = (modRM >> 6) & 0b11  # Bits 7-6
        reg_opcode = (modRM >> 3) & 0b111  # Bits 5-3
        r_m = modRM & 0b111  # Bits 2-0

        return mod, reg_opcode, r_m

    def parse_instruction(self):
        current_address = self.pointer

        while True:
            opcode = self.read_byte()
            if opcode is None:
                break

            raw_opcode = [opcode]
            instruction = self._parse_single_instruction(opcode)

            if instruction.startswith("Unknown opcode") or instruction.startswith("Error"):
                raw_opcode_str = ' '.join(f"{byte:02x}" for byte in raw_opcode)
                yield f"{current_address:#x}: {raw_opcode_str}  {instruction}"
            else:
                # Check for additional operand bytes based on the instruction
                if "imm32" in instruction:
                    raw_opcode.extend([self.held[self.pointer + i] for i in range(4)])
                    self.pointer += 4
                elif "disp8" in instruction:
                    raw_opcode.append(self.read_byte())
                elif "disp32" in instruction:
                    raw_opcode.extend([self.read_byte() for _ in range(4)])

                raw_opcode_str = ' '.join(f"{byte:02x}" for byte in raw_opcode)
                yield f"{current_address:#x}: {raw_opcode_str}    {instruction}"

            current_address = self.pointer

    def _parse_single_instruction(self, opcode):
        #Parses a single instruction.
        if opcode is None:
            return None
            #opcode if simple
        if opcode == 0xE8:  # CALL rel8
            rel_address = self.read_rel_address(4)
            if rel_address is None:
                return "Error CALL: Not enough bytes for rel32"
            return f"CALL {rel_address:#x}" #f means format
        if opcode == 0xE9:  # JMP rel32
            rel_address = self.read_rel_address(4)
            if rel_address is None:
                return "Error JMP: Not enough bytes for rel32"
            return f"JMP {rel_address:#x}"
        if opcode == 0xEB:  # JMP rel8
            rel_address = self.read_rel_address(1)
            return f"JMP {rel_address:#x}"
        if opcode == 0xC3:  # RETN
            return "RETN"
        if opcode == 0x66:  # OPSIZE
            return "OPSIZE"
        if opcode == 0x90:  # NOP
            return "NOP"
        if opcode == 0xC2:  # RETN Iw
            imm_address = self.read_rel_address(2)
            return f"RETN  {imm_address:#x}"
        if opcode == 0xCD:  # INT Ib
            imm_address = self.read_rel_address(1)
            return f"INT {imm_address:#x}"
        if opcode == 0x9C:  # PUSHF
            return "PUSHF"
        if opcode == 0x9D:  # POPF
            return "POPF"
        if opcode == 0xFA:  # CLI
            return "CLI"
        if opcode == 0xFB:  # STI
            return "STI"    
        

            #opcode if it needs a range and simple(register-based)        
        if 0x40 <= opcode <= 0x47:  # INC r32(default for the record since 64-bit mode also currently) 0x40-0x47   
                order = opcode - 0x40 #currently assuming little endian so needs to be that 
                return f"INC {self.reg_name[order]}" #INC specifyed
        
        if 0x48 <= opcode <= 0x4f:  # DEC r32 0x48-0x4f   
                order = opcode - 0x48 #currently little endian so needs to be that 
                return f"DEC {self.reg_name[order]}" #DEC specifyed
        
        if 0x50 <= opcode <= 0x57:  # PUSH r32 0x50-0x57   
                order = opcode - 0x50 #currently little endian so needs to be that 
                return f"PUSH {self.reg_name[order]}" #PUSH specifyed
        
        if 0x58 <= opcode <= 0x5f:  # POP r32 0x58-0x5f   
                order = opcode - 0x58 #currently little endian so needs to be that 
                return f"POP {self.reg_name[order]}" #POP specifyed
        
        if (0xB8 <= opcode <= 0xBF):  # MOV r32, imm32   
                order = opcode - 0xB8 #currently little endian so needs to be that
                imm32 = self.read_imm32()
                if imm32 is None:
                    return "Error MOV: Not enough bytes for imm32"
                return f"MOV {self.reg_name[order]}, {hex(imm32)}" #MOV specifyed then imm32(determine what that is) value
        

            #opcode but needs to be determined by modrm
        modrm_opcodes = {
        0x01: "ADD", 0x29: "SUB", 0x21: "AND",
        0x09: "OR", 0x31: "XOR", 0x39: "CMP",
        0x85: "TEST", 0x89: "MOV", 0x8B: "MOV",
        0x88: "MOV", 0x8A: "MOV"
        }
        if opcode in modrm_opcodes:
            mod, reg_opcode, r_m = self.read_modrm()
            if mod is None:
                return f"{modrm_opcodes[opcode]} Error: Not enough bytes for ModRM"
        
            addressing_mode, extra_bytes = self.get_addressing_mode(mod, r_m)

            # Read extra displacement bytes
            if extra_bytes > 0:
                if extra_bytes == 1:  # disp8
                    disp8 = self.read_byte()
                    addressing_mode = addressing_mode.replace("disp8", f"0x{disp8:02x}")
                elif extra_bytes == 4:  # disp32
                    disp32 = self.read_imm32()
                    addressing_mode = addressing_mode.replace("disp32", f"0x{disp32:x}")

            if opcode == 0x89:
                return f"MOV {addressing_mode}, {self.reg_name[reg_opcode]}"
            if opcode == 0x8B:
                return f"MOV {self.reg_name[reg_opcode]}, {addressing_mode}"
            return f"{modrm_opcodes[opcode]} {addressing_mode}, {self.reg_name[reg_opcode]}"
   
        else:
            return f"Unknown opcode: {hex(opcode)} (skipping)"

def main():
    """
    Reads the binary file, initializes the disassembler, and prints each disassembled instruction.
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

    disassembler = Recursive_Descent_Disassembler(file_content)

    # Loop through the instructions
    for instruction in disassembler.parse_instruction():
        print(instruction)

if __name__ == "__main__":
    main()