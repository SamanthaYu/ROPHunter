import pygtrie
from rop import ROPGadget
import unittest


class ROPTest(unittest.TestCase):
    def test_only_ret(self):
        rop_gadget = ROPGadget()
        start_offset = 0x1000
        code = b"\xc3"

        rop_gadget.galileo(start_offset, code)

        expected_trie = pygtrie.StringTrie()
        expected_trie["c3"] = "ret"

        actual_trie = rop_gadget.get_inst_trie()
        self.assertCountEqual(actual_trie.items(), expected_trie.items())

        expected_inst_addr = dict()
        actual_inst_addr = rop_gadget.get_inst_addr_dict()
        self.assertDictEqual(actual_inst_addr, expected_inst_addr)

    # Uses the example instruction from the paper, "Geometry of Innocent Flesh on the Bone"
    def test_valid_inst(self):
        rop_gadget = ROPGadget()
        start_offset = 0x1000
        code = b"\xc7\x07\x00\x00\x00\x0f\x95\x45\xc3"

        rop_gadget.galileo(start_offset, code)

        expected_trie = pygtrie.StringTrie()
        expected_trie["c3"] = "ret"
        expected_trie["c3/9545"] = "xchg eax, ebp"
        expected_trie["c3/9545/000f"] = "add byte ptr [rdi], cl"
        expected_trie["c3/9545/000f/0000"] = "add byte ptr [rax], al"
        expected_trie["c3/9545/00000f"] = "add byte ptr [rax], al"
        expected_trie["c3/9545/c7070000000f"] = "mov dword ptr [rdi], 0xf000000"
        expected_trie["c3/00000f9545"] = "add byte ptr [rax], al"

        actual_trie = rop_gadget.get_inst_trie()
        self.assertCountEqual(actual_trie.items(), expected_trie.items())

        # len(code) = 9
        # Expected instruction address: start_offset + len(code) - len(inst)
        expected_inst_addr = dict()
        expected_inst_addr["c3/9545"] = "0x1006"  # e.g. 0x1000 + 9 - 3 = 0x1006
        expected_inst_addr["c3/9545/000f"] = "0x1004"
        expected_inst_addr["c3/9545/000f/0000"] = "0x1002"
        expected_inst_addr["c3/9545/00000f"] = "0x1003"
        expected_inst_addr["c3/9545/c7070000000f"] = "0x1000"
        expected_inst_addr["c3/00000f9545"] = "0x1003"

        actual_inst_addr = rop_gadget.get_inst_addr_dict()
        self.assertDictEqual(actual_inst_addr, expected_inst_addr)


if __name__ == '__main__':
    unittest.main()