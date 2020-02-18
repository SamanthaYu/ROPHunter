from capstone import *
import pygtrie

CODE = b"\xf7\xc7\x07\x00\x00\x00\x0f\x95\x45\xc3"

def galileo():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(CODE, 0x1000):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))


if __name__== "__main__":
    galileo()