import argparse


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

        for addr, gadget in sorted(self.rop_gadget_dict.items()):
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

    def write_false_positives(self):
        false_positives_file = open("evaluation/false_positives.txt", "w")

        for addr, gadget in sorted(self.rop_hunter_dict.items()):
            if addr not in self.rop_gadget_dict:
                hex_addr = str(hex(addr))
                gadget_str = hex_addr + " | " + gadget
                false_positives_file.write(gadget_str)
        false_positives_file.close()

    def write_false_negatives(self):
        false_negatives_file = open("evaluation/false_negatives.txt", "w")

        for addr, gadget in sorted(self.rop_gadget_dict.items()):
            if addr not in self.rop_hunter_dict:
                hex_addr = str(hex(addr))
                gadget_str = hex_addr + " | " + gadget
                false_negatives_file.write(gadget_str)
        false_negatives_file.close()


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Evaluate ROP gadgets returned by ROPgadget and ROPHunter")
    arg_parser.add_argument("rop_gadget_path", help="File path containing the gadgets returned by ROPgadget")
    arg_parser.add_argument("rop_hunter_path", help="File path containing the gadgets returned by ROPHunter")
    args = arg_parser.parse_args()

    evaluate_rop = EvaluateROP()
    evaluate_rop.rop_gadget_path = args.rop_gadget_path
    evaluate_rop.rop_hunter_path = args.rop_hunter_path

    evaluate_rop.parse_rop_gadget_file()
    evaluate_rop.parse_rop_hunter_file()

    evaluate_rop.write_identical_addr()
    evaluate_rop.write_false_positives()
    evaluate_rop.write_false_negatives()