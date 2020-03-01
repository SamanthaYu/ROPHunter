import pygtrie
from rop import galileo, get_instr_trie
import unittest


class ROPTest(unittest.TestCase):
    def test_only_ret(self):
        code = b"\xc3"
        galileo(code)
        actual_trie = get_instr_trie()

        expected_trie = pygtrie.StringTrie()
        expected_trie["c3"] = "ret"

        self.assertCountEqual(actual_trie.items(), expected_trie.items())

    # Uses the example instruction from the paper, "Geometry of Innocent Flesh on the Bone"
    def test_valid_inst(self):
        code = b"\xc7\x07\x00\x00\x00\x0f\x95\x45\xc3"
        galileo(code)
        actual_trie = get_instr_trie()

        expected_trie = pygtrie.StringTrie()
        expected_trie["c3"] = "ret"
        expected_trie["c3/9545"] = "xchg eax, ebp"
        expected_trie["c3/9545/000f"] = "add byte ptr [rdi], cl"
        expected_trie["c3/9545/000f/0000"] = "add byte ptr [rax], al"
        expected_trie["c3/9545/00000f"] = "add byte ptr [rax], al"
        expected_trie["c3/9545/c7070000000f"] = "mov dword ptr [rdi], 0xf000000"
        expected_trie["c3/00000f9545"] = "add byte ptr [rax], al"

        self.assertCountEqual(actual_trie.items(), expected_trie.items())

if __name__ == '__main__':
    unittest.main()