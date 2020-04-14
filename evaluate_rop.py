import sys

class EvaluateROP:
    def __init__(self):
        self.rop_gadget_path = ""
        self.rop_hunter_path = ""

        self.rop_gadget_dict = dict()
        self.rop_hunter_dict = dict()

    def parse_rop_gadget_file(self):
        with open(self.rop_gadget_path, "r") as f:
            for line in f:
                # We skip parsing any lines that don't contain " : "; e.g. Header lines
                if " : " not in line:
                    continue

                [addr, gadget] = line.split(" : ", 1)
                addr_hex = int(addr, 16)
                self.rop_gadget_dict[addr_hex] = gadget.strip() + " ; \n"

    def parse_rop_hunter_file(self):
        with open(self.rop_hunter_path, "r") as f:
            for line in f:
                addr = line.split(" : ")[0]
                addr_hex = int(addr, 16)
                gadget = line.split(" | ")[1]
                self.rop_hunter_dict[addr_hex] = gadget

    def write_identical_addr(self):
        matches_file = open("evaluation/matches.txt", "w")
        mismatches_file = open("evaluation/mismatches.txt", "w")

        for addr, gadget in self.rop_gadget_dict.items():
            if addr in self.rop_hunter_dict:
                hex_addr = str(hex(addr))
                gadget_str = hex_addr + " | " + gadget
                rop_hunter_gadget = self.rop_hunter_dict[addr]

                if gadget == rop_hunter_gadget:
                    matches_file.write(gadget_str)
                else:
                    # Create a string with the same number of spaces as hex_addr with " | "
                    spaces = " "*(len(hex_addr) + 3)
                    hunter_gadget_str = spaces + rop_hunter_gadget
                    mismatches_file.write(gadget_str)
                    mismatches_file.write(hunter_gadget_str)

        matches_file.close()
        mismatches_file.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("The ROP gadget files were not provided")

    evaluate_rop = EvaluateROP()
    evaluate_rop.rop_gadget_path = sys.argv[1]
    evaluate_rop.rop_hunter_path = sys.argv[2]

    evaluate_rop.parse_rop_gadget_file()
    evaluate_rop.parse_rop_hunter_file()
    evaluate_rop.write_identical_addr()