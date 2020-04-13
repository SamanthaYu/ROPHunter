# CMPT 479 Project - ROP Gadget Hunter

## Find Base Address of libc
- For now, we'll assume that ASLR has been disabled:
```
sudo sysctl -w kernel.randomize_va_space=0
```

- We can find the base address of libc by using gdb on the vulnerable executable:
```
b main
run
info proc mappings
```

- gdb will probably return several mappings to libc
- The mapping with the lowest offset will be the base address of libc
- e.g. In the below output, we will use `0x7ffff77dd000` as our base address and `/lib/x86_64-linux-gnu/libc-2.27.so` as the path to libc
```
          Start Addr           End Addr       Size     Offset objfile
      0x7ffff77dd000     0x7ffff79c4000   0x1e7000        0x0 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff79c4000     0x7ffff7bc4000   0x200000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7bc4000     0x7ffff7bc8000     0x4000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7bc8000     0x7ffff7bca000     0x2000   0x1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
```

## How to Find Gadgets
```
python rop.py <libc_path>
```

## How to Create an ROP Chain
- The addresses of the gadgets are calculated by adding the libc base address with the address of the gadgets

## How to Run ROPgadget
```
ROPgadget --binary /lib/x86_64-linux-gnu/libc-2.27.so
```