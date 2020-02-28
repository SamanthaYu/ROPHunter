from capstone import *
import pygtrie

# max instr length on x86_64
max_inst_len = 15
instr_trie = pygtrie.StringTrie()

code = b"\xf7\x5d\xc3\xc7\x07\x00\xc9\xc3\x00\x00\x0f\xc9\xc3\x95\x45\xc3"
bitstring = code.hex()


# initialize python class for capstone
md = Cs(CS_ARCH_X86, CS_MODE_64)


# print all gadgets in the trie
def print_gadgets():
    for key in instr_trie.keys():
        if not instr_trie.has_subtrie(key):
            prefixes = instr_trie.prefixes(key)
            print(key, end="")
            for prefix in prefixes:
                print(" | " + prefix.value, end="")
            print()


def get_instr_str(disas_instr):
    return disas_instr.mnemonic + " " + disas_instr.op_str;



prev_inst = "0"

def is_instr_boring(disas_instr):
    global prev_inst

    if disas_instr.mnemonic == "ret" or disas_instr.mnemonic == "jmp":
        prev_inst = disas_instr.mnemonic
        return True

    if disas_instr.mnemonic == "leave" and prev_inst == "ret":
        prev_inst = disas_instr.mnemonic
        return True

    if get_instr_str(disas_instr) == "pop rbp" and prev_inst == "ret":
        prev_inst = disas_instr.mnemonic
        return True

    prev_inst = disas_instr.mnemonic

    return False


# MISSING: check if instr is boring
def build_from(pos, parent):
    for step in range(1, max_inst_len):
        instr = code[pos - step : pos - 1]
        if pos - step < 0:
            continue


        num_instr = 0
        for i in md.disasm(instr, 0x1000):
            # print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            disas_instr = i
            num_instr += 1
            if num_instr > 1:
                break

        #this part will only be entered if disasm finds valid instructions
        # want only to extract single instructions
        # TODO: add boring instr check here as well
        if num_instr == 1:
            if not is_instr_boring(disas_instr):
                trie_key = parent + "/" + instr.hex()
                instr_trie[trie_key] = get_instr_str(disas_instr)
                build_from(pos - step + 1, trie_key)


def galileo():
    # place root c3 in the trie (key: c3, value: ret)
    instr_trie["c3"] = "ret"
    global prev_inst

    for i in range(0, len(code)):
        print("byte is ", code[i:i+1].hex())

        if code[i:i+1] == b"\xc3":
            prev_inst = "ret"
            print("found ret")
            build_from(i + 1, "c3")


if __name__ == "__main__":
    galileo()
    print_gadgets()