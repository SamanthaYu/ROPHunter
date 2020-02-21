from capstone import *
import pygtrie

# max instr length on x86_64
max_inst_len = 15
instr_trie = pygtrie.StringTrie()

code = b"\xf7\xc7\x07\x00\x00\x00\x0f\x95\x46\xc3"
bitstring = code.hex()

#initialize python class for capstone
md = Cs(CS_ARCH_X86, CS_MODE_64)

#print all gadgets in the trie
def print_gadgets():
    for key in instr_trie.keys():
        print("key is " + key)
        print("instruction is " + instr_trie[key])

#MISSING: check if instr is boring
def build_from(pos, parent): 
    for step in range(1, max_inst_len):
        instr = code[pos - step : pos - 1]
        if pos - step < 0:
            continue;

        #check we havent gone over this instruction yet
        if(not instr_trie.has_node(instr.hex())):
                instr_string = ""
                num_instr = 0
                for i in md.disasm(instr, 0x1000):
                    # print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
                    instr_string = i.mnemonic + " " + i.op_str
                    num_instr+=1
                    if(num_instr > 1):
                        break
                # this part will only be entered if disasm finds valid instructions
                # want only to extract single instructions 
                #TODO: add boring instr check here as well
                if(num_instr == 1):
                    trie_key = parent  + "\\" + instr.hex()
                    instr_trie[trie_key] = instr_string
                    build_from(pos - step, trie_key)    
    
def galileo():
    # place root c3 in the trie (key: c3, value: ret)
    instr_trie["c3"] = "ret"

    for i in range(0, len(code)):
        print("byte is ", code[i : i+1].hex())

        if code[i : i + 1] == b"\xc3":
            print("found ret")
            build_from(i+1, "c3")

if __name__== "__main__":
    galileo()
    print_gadgets()