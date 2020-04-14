# CMPT 479 Project - ROPHunter

## Setup
- We'll disable ASLR:
```
sudo sysctl -w kernel.randomize_va_space=0
```

- We'll be running the following instructions within a Python virtualenv:
```
python3 -m venv venv
source venv/bin/activate
```

- Install all necessary requirements:
```
pip install -r requirements.txt
```

## Find Base Address of libc
- We can find the base address of libc by using gdb on the vulnerable executable:
```
gdb examples/vuln
```

- Inside gdb, we run:
```
b main
run
info proc mappings
```

- gdb will probably return several mappings to libc
- The mapping with the lowest offset will be the base address of libc
- e.g. In the below output, we will use `0xb7e09000` as our base address and `/lib/i386-linux-gnu/libc-2.23.so` as the path to libc
```
	Start Addr   End Addr       Size     Offset objfile
	0xb7e09000 0xb7fb9000   0x1b0000        0x0 /lib/i386-linux-gnu/libc-2.23.so
	0xb7fb9000 0xb7fbb000     0x2000   0x1af000 /lib/i386-linux-gnu/libc-2.23.so
	0xb7fbb000 0xb7fbc000     0x1000   0x1b1000 /lib/i386-linux-gnu/libc-2.23.so
```

## How to Find Gadgets
```
python3 rop.py <binary> <architecture> <mode>
```
For example:
```
python3 rop.py /lib/i386-linux-gnu/libc-2.23.so x86 32
```

## How to Create an ROP Chain
- The addresses of the gadgets are calculated by adding the libc base address with the address of the gadgets

## How to Run ROPgadget
```
ROPgadget --binary <libc_path> --rawArch x86 --rawMode 32
```

## How to Evaluate Gadgets Found by ROPgadget vs. ROPHunter
```
python3 evaluate_rop.py <ropgadget_path> <rophunter_path>
```

If we run the following command, it will write the gadgets to `evaluation/`:
```
python3 evaluate_rop.py gadgets/x86_32/libc_ropgadget.txt gadgets/x86_32/libc_rophunter.txt
```

- `matches.txt` and `mismatches.txt` correspond to gadgets that both ROPgadget and ROPHunter found at the same address.
- `false_positives.txt` refers to gadgets that only ROPHunter found
- `false_negatives.txt` refers to gadgets that only ROPgadget found