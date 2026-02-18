class Recursive_Descent_Dissasembler :
    # Constructor(just holds)
    def __init__(self, binary_code) :
        self.held = binary_code
        #when I need to go recursion need to make variable to hold the pointer
        self.pointer = 0
        
    def read_byte(self) :
        # reads the next byte from the code and stops if it reaches the end
        if self.pointer >= len(self.held) :
            return None
        byte = self.held[self.pointer]
        self.pointer += 1
        return byte

    def parse_instruction(self):
        #Parses a single instruction.
        opcode = self.read_byte()
        if opcode is None:
            return None
        if 0x50 <= opcode <= 0x57:  # PUSH r32 max?, imm32   
                reg = opcode - 0xB8 #currently little edian so needs to be that
                imm32 = self.read_byte() + (self.read_byte() << 8) + (self.read_byte() << 16) + (self.read_byte() << 24)
                reg_name = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
                reg = opcode - 0xB8
                register_name = reg_name[reg]
                return f"MOV {register_name}, {hex(imm32)}" #MOV specifyed then imm32(determine what that is) value

        if 0xB8 <= opcode <= 0xBF:  # MOV r32, imm32   
                reg = opcode - 0xB8 #currently little edian so needs to be that
                imm32 = self.read_byte() + (self.read_byte() << 8) + (self.read_byte() << 16) + (self.read_byte() << 24)
                reg_name = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
                reg = opcode - 0xB8
                register_name = reg_name[reg]
                return f"MOV {register_name}, {hex(imm32)}" #MOV specifyed then imm32(determine what that is) value
        else:
            return f"Unknown opcode: {hex(opcode)}"
