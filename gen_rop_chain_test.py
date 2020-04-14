from gen_rop_chain import ROPChain
import unittest

class ROPChainTest(unittest.TestCase):
    def test_get_gadget_addr(self):
        rop_chain = ROPChain()
        start_offset = 0x1000
        gadget_bytes = "c3/9545/000f/0000"
        gadget_suffix = "xchg eax, ebp ; ret ;" # Corresponds to "c3/9545"

        actual_addr = rop_chain.get_gadget_addr(start_offset, gadget_bytes, gadget_suffix)
        expected_addr = 0x1004
        self.assertEqual(hex(actual_addr), hex(expected_addr))

if __name__ == '__main__':
    unittest.main()