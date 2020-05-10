# CMPT 479 Project - ROPHunter

## Setup
- We'll be using the virtual machine from assignment 1: https://vault.sfu.ca/index.php/s/pq2sVjmUlmfBWwl
- We'll be running the following instructions within a Python virtualenv:
```
python3 -m venv venv
source venv/bin/activate
```
- Install all necessary requirements:
```
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## How to Find Gadgets
```
python3 rop.py --binary <binary> --arch <architecture> --mode <mode>
```
- For example:
```
python3 rop.py --binary /lib/i386-linux-gnu/libc-2.23.so --arch x86 --mode 32 --output
```
*Warning, this step may take a few minutes* 

## How to Launch a Shell in a Vulnerable Program
- Please see [shellcode/README.md](shellcode/README.md)

## How to Run ROPgadget
```
ROPgadget --binary <libc_path> --rawArch x86 --rawMode 32
```

## How to Evaluate Gadgets Found by ROPgadget vs. ROPHunter
```
python3 evaluate_rop.py --rop_gadget_path <ropgadget_path> --rop_hunter_path <rophunter_path>
```
- For example:
```
python3 evaluate_rop.py --rop_gadget_path gadgets/x86_32/libc_ropgadget.txt --rop_hunter_path gadgets/x86_32/libc_rophunter.txt
```
- `evaluation/matches.txt` and `evaluation/mismatches.txt` correspond to gadgets that both ROPgadget and ROPHunter found at the same address.
- `evaluation/false_positives.txt` refers to gadgets that only ROPHunter found
- `evaluation/false_negatives.txt` refers to gadgets that only ROPgadget found
