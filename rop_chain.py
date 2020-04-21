import argparse
# from collections import OrderedDict 

class ROPChain:
    def __init__(self, rop_hunter_file):
        self.gadget_dict = dict()
        self.rop_hunter_file = rop_hunter_file

    def parse_gadgets_file(self):
        with open(self.rop_hunter_file, "r") as f:
            for line in f:
                addr, line_no_addr = line.split(" : ", 1)
                addr_hex = int(addr, 16)

                gadget_bytes, gadget = line_no_addr.split(" | ", 1)
                gadget = gadget.strip()
                self.gadget_dict[gadget] = (addr_hex, gadget_bytes)

    def get_gadget_addr(self, start_addr, gadget_bytes, gadget_suffix):
        # We store the base address of the entire gadget
        # If we want a subset of this gadget, we will have to calculate this new address
        suffix_num_inst = gadget_suffix.count(";")
        total_num_inst = gadget_bytes.count("/") + 1    # Add 1 because there is no additional / at the end of a gadget
        bytes_list = gadget_bytes.split("/")
        gadget_offset = 0

        for i in range(suffix_num_inst, total_num_inst):
            gadget_offset += round(len(bytes_list[i]) / 2)

        return start_addr + gadget_offset


    def get_gadget(self, gadget_suffix):
        # Find a gadget containing this suffix
        possible_gadgets = [val for key, val in self.gadget_dict.items() if key.endswith(gadget_suffix)]
        if len(possible_gadgets) < 1:
            print("Could not find the gadget: " + gadget_suffix)
            return None

        possible_gadget = possible_gadgets[0]
        return self.get_gadget_addr(possible_gadget[0], possible_gadget[1], gadget_suffix)

