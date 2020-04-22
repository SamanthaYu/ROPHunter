import argparse
from capstone import *
from elftools.elf.elffile import ELFFile
import pygtrie

import multiprocessing as mp
import os


class ROPHunter:
    def __init__(self, arch, mode, parallelism):
        # TODO: Customize the max inst length for other achitectures besides x86_64
        self.max_inst_len = 15
        self.max_inst_per_gadget = 3
        self.inst_trie = pygtrie.StringTrie()

        # Used to keep track of the starting addresses of the gadgets
        self.inst_addr_dict = dict()

        # initialize python class for capstone
        self.md = Cs(arch, mode)

        # Initialize prev_inst to null; used to find boring instructions
        self.prev_inst = "0"

        # Whether to run serial or parallel version
        self.parallel = parallelism

    def read_binary(self, file_path):
        with open(file_path, "rb") as f:
            bin_file = ELFFile(f)
            bin_text = bin_file.get_section_by_name('.text')
            bin_addr = bin_text["sh_addr"]
            bin_data = bin_text.data()

            # print(bin_addr)
            # print(''.join([r'\x{:02x}'.format(c) for c in bin_data]))
        # print(binascii.hexlify(binary_file))
        return [bin_addr, bin_data]

    # print all gadgets in the trie
    def print_gadgets(self):
        for key in self.inst_trie.keys():
            if not self.inst_trie.has_subtrie(key):
                prefixes = self.inst_trie.prefixes(key)
                gadget_str = ""

                for prefix in prefixes:
                    gadget_str = prefix.value.strip() + " ; " + gadget_str

                gadget_str = self.inst_addr_dict[key] + " : " + key + " | " + gadget_str
                print(gadget_str)

    def get_inst_str(self, disas_inst):
        return disas_inst[2] + " " + disas_inst[3]

    def get_inst_trie(self):
        return self.inst_trie

    def get_inst_addr_dict(self):
        return self.inst_addr_dict

    def is_inst_boring(self, disas_instr):
        if disas_instr[2] == "ret" or disas_instr[2] == "jmp":
            self.prev_inst = disas_instr[2]
            return True

        if disas_instr[2] == "leave" and self.prev_inst == "ret":
            self.prev_inst = disas_instr[2]
            return True

        if self.get_inst_str(disas_instr) == "pop rbp" and self.prev_inst == "ret":
            self.prev_inst = disas_instr[2]
            return True

        self.prev_inst = disas_instr[2]
        return False

    def is_gadget_duplicate(self, trie_key, disas_inst):
        orig_key = trie_key[:-2]
        if self.inst_trie.has_key(orig_key):
            if self.inst_trie[orig_key] == self.get_inst_str(disas_inst):
                return True
        return False

    def build_from(self, code, pos, parent, ret_offset):
        for step in range(1, self.max_inst_len):
            inst = code[pos - step : pos - 1]
            if pos - step >= pos - 1:
                continue

            if pos - step < 0:
                continue

            num_inst = 0
            for i in self.md.disasm_lite(inst, ret_offset - step + 1):
                # disas_inst is a tuple of (address, size, mnemonic, op_str)
                disas_inst = i
                num_inst += 1
                if num_inst > 1:
                    break

            # this part will only be entered if disasm finds valid instructions
            # want only to extract single instructions
            if num_inst == 1:
                trie_key = parent + "/" + inst.hex()

                # If we don't restrict the number of instructions per gadget, the number of paths to explore explodes
                if trie_key.count('/') > self.max_inst_per_gadget:
                    break

                if not self.is_inst_boring(disas_inst) and not self.is_gadget_duplicate(trie_key, disas_inst):
                    self.inst_trie[trie_key] = self.get_inst_str(disas_inst)
                    self.inst_addr_dict[trie_key] = hex(disas_inst[0])
                    self.build_from(code, pos - step + 1, trie_key, disas_inst[0])

    def galileo(self, start_offset, code):
        if self.parallel == 0:
            return galileo_serial
        else:
            return galileo_parallel

    def galileo_serial(self, start_offset, code):
        # place root c3 in the trie (key: c3, value: ret)
        self.inst_trie["c3"] = "ret"

        for i in range(0, len(code)):
            # print(binascii.hexlify(code[i:i+1]))
            # print("byte is ", code[i:i+1].hex())

            if code[i:i+1] == b"\xc3":
                self.prev_inst = "ret"
                self.build_from(code, i + 1, "c3", start_offset + i)

        return self.inst_trie

    def galileo_parallel(self, start_offset, code):
        # determine num of cpus on machine for optimal parallelism
        N = mp.cpu_count()
        print("running on galileo in parallel on " + N + " cpus:\n")
        
        # place root c3 in the trie (key: c3, value: ret)
        self.inst_trie["c3"] = "ret"

        with mp.Pool(processes = N) as p:
            for i in range(0, len(code)):
                # print(binascii.hexlify(code[i:i+1]))
                # print("byte is ", code[i:i+1].hex())

                if code[i:i+1] == b"\xc3":
                    self.prev_inst = "ret"
                    p.apply_async(self.build_from_parallel, (code, i + 1, "c3", start_offset + i))

        return self.inst_trie

if __name__ == "__main__":
    # TODO: Add more architectures
    arch_dict = {
        "x86": CS_ARCH_X86
    }

    mode_dict = {
        "16": CS_MODE_16,
        "32": CS_MODE_32,
        "64": CS_MODE_64
    }

    arg_parser = argparse.ArgumentParser(description="Find ROP gadgets within a binary file")
    arg_parser.add_argument("binary", help="File path of the binary executable")
    arg_parser.add_argument("arch", help="Hardware architecture", choices=arch_dict.keys())
    arg_parser.add_argument("mode", help="Hardware mode", choices=mode_dict.keys())
    # 0 for serial, 1 for parallelism
    arg_parser.add_argument("parallel", help="Parallelism", choices=range(0, 2))
    args = arg_parser.parse_args()

    rop_hunter = ROPHunter(arch_dict[args.arch], mode_dict[args.mode], parallelism)

    # code = b"\xf7\xc7\x07\x00\x00\x00\x0f\x95\x45\xc3\xf7\xc7\x07\x00\x00\x00\x0f\x95\x45\xc3"
    [start_offset, code] = rop_hunter.read_binary(args.binary)

    rop_hunter.galileo(start_offset, code)
    rop_hunter.print_gadgets()
