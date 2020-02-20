from capstone import *
import pygtrie

max_inst_len = 6
instr_trie = pygtrie.StringTrie()

code = b"\xf7\xc7\x07\x00\x00\x00\x0f\x95\x46\xc3"
bitstring = code.hex()

#initialize python class for capstone
md = Cs(CS_ARCH_X86, CS_MODE_64)

def build_from(pos, parent):
    for step in range(1, max_inst_len):
        instr = code[step - pos : pos - 1]
        print("instr is", instr.hex())

        # this part will only be entered if disasm finds valid instructions
        if(not instr_trie.has_node(instr.hex())):
            if md.disasm(instr, 0x1000):
                instr_list = []
                for i in md.disasm(instr, 0x1000):
                    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
                    instr_list.append((i.mnemonic + " " + i.op_str))

                instr_trie[instr.hex()] = instr_list
                print("instructions are ", instr_list)
            
        # if instr:
        #     # check if insn is in tree
        #     #check if insn is boring
        #     build_from(pos - step, instr)
    


def galileo():
    # place root c3 in the trie (key: c3, value: ret)

    for i in range(0, len(code)):
        print("byte is ", code[i : i+1].hex())

        if code[i : i + 1] == b"\xc3":
            print("found ret")
            build_from(i+1, "c3")

if __name__== "__main__":
    galileo()