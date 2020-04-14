import argparse

class ROPChain:
    def __init__(self):
        self.gadget_dict = dict()

    def parse_gadgets_file(self, rop_hunter_file):
        with open(rop_hunter_file, "r") as f:
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
        bytes_list = gadget_bytes.split("/")
        gadget_offset = 0

        for i in range(suffix_num_inst, 0, -1):
            gadget_offset += round(len(bytes_list[i]) / 2)

        return start_addr + gadget_offset


    def get_gadget(self, gadget_suffix):
        # Find a gadget containing this suffix
        possible_gadgets = [val for key, val in self.gadget_dict.items() if key.endswith(gadget_suffix)]
        if len(possible_gadgets) < 1:
            return None

        possible_gadget = possible_gadgets[0]
        return self.get_gadget_addr(possible_gadget[0], possible_gadget[1], gadget_suffix)
    

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Create a ROP chain using the gadgets found")
    arg_parser.add_argument("gadgets", help="File path of the gadgets returned by ROPgadget")
    args = arg_parser.parse_args()

    rop_chain = ROPChain()
    rop_chain.parse_gadgets_file(args.gadgets)

    gadget_addr = rop_chain.get_gadget("add byte ptr es:[ecx], dh ; ret ;")
    print(gadget_addr)