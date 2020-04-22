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
pip install -r requirements.txt
```

## How to Find Gadgets
```
python3 rop.py <binary> <architecture> <mode>
```
- For example:
```
python3 rop.py /lib/i386-linux-gnu/libc-2.23.so x86 32
```
*Warning, this step may take a few minutes* 

## How to Launch a Shell in a Vulnerable Program
- Please see <https://github.com/SamanthaYu/cmpt479-project/blob/samantha/examples/README.md>

## How to Run ROPgadget
```
ROPgadget --binary <libc_path> --rawArch x86 --rawMode 32
```

## How to Evaluate Gadgets Found by ROPgadget vs. ROPHunter
```
python3 evaluate_rop.py <ropgadget_path> <rophunter_path>
```
- For example:
```
python3 evaluate_rop.py gadgets/x86_32/libc_ropgadget.txt gadgets/x86_32/libc_rophunter.txt
```
- `evaluation/matches.txt` and `evaluation/mismatches.txt` correspond to gadgets that both ROPgadget and ROPHunter found at the same address.
- `evaluation/false_positives.txt` refers to gadgets that only ROPHunter found
- `evaluation/false_negatives.txt` refers to gadgets that only ROPgadget found
