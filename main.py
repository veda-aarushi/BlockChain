from dataclasses import dataclass
from typing import Any, List

"""
//Input
We are given:
  - transactions to store in blocks
  - a blockchain that creates blocks and validates immutability

Constraints:
  - No SHA-256 (custom hash)
  - PoW depends on 2 dynamic parameters
  - Blocks contain attack-resilient metadata
  - No peers required
"""

# //what DS/Algo:
"""
DS:
  - list for mempool
  - list for chain

Algo:
  - custom hash
  - merkle root
  - dynamic PoW
  - chain validation
"""

# //what do we do with the data:
"""
Flow:
  1) add_transaction(tx)
  2) mine_block(): build metadata -> run PoW -> append block
  3) is_valid(): verify links + hashes + PoW
"""

# //Output
"""
We print blocks with:
  height, prev_hash, txs, merkle, difficulty_bits, window_mod, metadata_hash, auth_tag, nonce, block_hash
We print chain valid? True/False
"""


# ============================================================
# Commit #2: Block Data Structure
# ============================================================

@dataclass
class Block:
    height: int
    timestamp: float
    prev_hash: str
    transactions: List[Any]

    merkle: str
    difficulty_bits: int
    window_mod: int
    metadata_hash: str
    auth_tag: str

    nonce: int
    block_hash: str


# ============================================================
# Commit #3: Custom Hash (AuroHash-256) — NOT SHA-256
# ============================================================

def _rotl32(x: int, r: int) -> int:
    """Rotate-left a 32-bit integer."""
    x &= 0xFFFFFFFF
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def aurohash_256(data: bytes) -> str:
    """
    Custom 256-bit hash function for coursework.
    - Input: bytes
    - Output: 64 hex chars (256 bits)
    NOTE: Not a standard crypto hash; used to satisfy 'no SHA-256' constraint.
    """
    s = [
        0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
        0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89
    ]

    pad = (4 - (len(data) % 4)) % 4
    data += b"\x80"
    if pad:
        data += b"\x00" * (pad - 1)

    for i in range(0, len(data), 4):
        w = int.from_bytes(data[i:i + 4], "little") & 0xFFFFFFFF

        s[0] = (s[0] + w) & 0xFFFFFFFF
        s[1] ^= _rotl32(s[0], 5)
        s[2] = (s[2] + _rotl32(s[1], 11)) & 0xFFFFFFFF
        s[3] ^= _rotl32(s[2], 17)

        s[4] = (s[4] + (s[3] ^ 0x9E3779B9)) & 0xFFFFFFFF
        s[5] ^= _rotl32(s[4], 7)
        s[6] = (s[6] + _rotl32(s[5], 13)) & 0xFFFFFFFF
        s[7] ^= _rotl32(s[6], 19)

        s[0] ^= s[5]
        s[3] = (s[3] + s[7]) & 0xFFFFFFFF
        s[6] ^= _rotl32(s[2], 3)

    for _ in range(16):
        s[0] = (s[0] + _rotl32(s[7], 9)) & 0xFFFFFFFF
        s[1] ^= _rotl32(s[0], 3)
        s[2] = (s[2] + (s[1] ^ 0x7F4A7C15)) & 0xFFFFFFFF
        s[3] ^= _rotl32(s[2], 15)
        s[4] = (s[4] + _rotl32(s[3], 7)) & 0xFFFFFFFF
        s[5] ^= _rotl32(s[4], 11)
        s[6] = (s[6] + _rotl32(s[5], 19)) & 0xFFFFFFFF
        s[7] ^= _rotl32(s[6], 5)

    return "".join(f"{x:08x}" for x in s)


# ============================================================
# Commit #4: Merkle Root for Transaction Integrity
# ============================================================

def merkle_root(transactions: List[Any]) -> str:
    """
    Builds a Merkle root for the transactions.
    Any transaction change -> different leaf hash -> different merkle root.
    """
    if not transactions:
        return aurohash_256(b"")

    layer = [aurohash_256(str(tx).encode("utf-8")) for tx in transactions]

    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])

        next_layer = []
        for i in range(0, len(layer), 2):
            combined = (layer[i] + layer[i + 1]).encode("utf-8")
            next_layer.append(aurohash_256(combined))
        layer = next_layer

    return layer[0]


def main():
    # quick local test (OPTIONAL)
    print("hash('hello') =", aurohash_256(b"hello"))
    print("merkle(['a','b']) =", merkle_root(["a", "b"]))


if __name__ == "__main__":
    main()
