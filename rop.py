import binascii
from capstone import *
import pygtrie

# max instr length on x86_64
max_inst_len = 15
max_inst_per_gadget = 3
instr_trie = pygtrie.StringTrie()

# initialize python class for capstone
md = Cs(CS_ARCH_X86, CS_MODE_64)


def read_binary(file_path):
    # TODO: Read only the executable segment (We're currently parsing the ELF headers as well)
    with open(file_path, "rb") as f:
        binary_file = f.read()
    print(''.join([r'\x{:02x}'.format(c) for c in binary_file]))
    # print(binascii.hexlify(binary_file))
    return binary_file


# write all gadgets in the trie to the file, f
def write_gadgets(f):
    for key in instr_trie.keys():
        gadget_str = ""
        if not instr_trie.has_subtrie(key):
            prefixes = instr_trie.prefixes(key)
            gadget_str += key
            for prefix in prefixes:
                gadget_str = gadget_str + " | " + prefix.value
            gadget_str += "\n"
        f.write(gadget_str)


def get_instr_str(disas_instr):
    return disas_instr.mnemonic + " " + disas_instr.op_str


def get_instr_trie():
    return instr_trie


def is_instr_boring(disas_instr):
    if disas_instr.mnemonic == "ret":
        return True
    return False


def is_gadget_duplicate(trie_key, disas_instr):
    orig_key = trie_key[:-2]
    if instr_trie.has_key(orig_key):
        if instr_trie[orig_key] == get_instr_str(disas_instr):
            return True
    return False


# MISSING: check if instr is boring
def build_from(code, pos, parent):
    for step in range(1, max_inst_len):
        instr = code[pos - step : pos - 1]
        if pos - step >= pos - 1:
            continue

        if pos - step < 0:
            continue

        num_instr = 0
        for i in md.disasm(instr, 0x1000):
            # print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            disas_instr = i
            num_instr += 1
            if num_instr > 1:
                break

        # this part will only be entered if disasm finds valid instructions
        # want only to extract single instructions
        # TODO: add boring instr check here as well
        if num_instr == 1:
            trie_key = parent + "/" + instr.hex()

            # If we don't restrict the number of instructions per gadget, the number of paths to explore will explode
            if trie_key.count('/') > max_inst_per_gadget:
                break

            if not is_instr_boring(disas_instr) and not is_gadget_duplicate(trie_key, disas_instr):
                instr_trie[trie_key] = get_instr_str(disas_instr)
                build_from(code, pos - step + 1, trie_key)


def galileo(code):
    # place root c3 in the trie (key: c3, value: ret)
    instr_trie["c3"] = "ret"
    print("Code len: " + str(len(code)))

    for i in range(0, len(code)):
        # print(binascii.hexlify(code[i:i+1]))
        # print("byte is ", code[i:i+1].hex())

        if code[i:i+1] == b"\xc3":
            print("found ret: " + str(i))
            build_from(code, i + 1, "c3")

    return instr_trie

if __name__ == "__main__":
    # code = b"\xf7\xc7\x07\x00\x00\x00\x0f\x95\x45\xc3\xf7\xc7\x07\x00\x00\x00\x0f\x95\x45\xc3"
    code = read_binary("/lib/x86_64-linux-gnu/libc.so.6")

    galileo(code)

    print("Writing gadgets to file")
    with open("gadgets/libc.txt", "w+") as f:
        write_gadgets(f)
