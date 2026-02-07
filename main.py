from dataclasses import dataclass
from typing import Any, List, Tuple
import time
import argparse

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
  - dynamic PoW (difficulty_bits + window_mod)
  - chain validation (immutability proof)
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
# Block Data Structure
# ============================================================

@dataclass
class Block:
    height: int
    timestamp: float
    prev_hash: str
    transactions: List[Any]

    # attack-resilient metadata
    merkle: str
    difficulty_bits: int    # dynamic parameter #1
    window_mod: int         # dynamic parameter #2
    metadata_hash: str
    auth_tag: str

    # PoW fields
    nonce: int
    block_hash: str


# ============================================================
# Custom Hash (AuroHash-256) — NOT SHA-256
# ============================================================

def _rotl32(x: int, r: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def aurohash_256(data: bytes) -> str:
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
# Merkle Root (Transaction Integrity)
# ============================================================

def merkle_root(transactions: List[Any]) -> str:
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


# ============================================================
# Blockchain (PoW + Validation)
# ============================================================

class Blockchain:
    def __init__(
        self,
        chain_id: str = "LOCAL-CHAIN-1",
        secret_key: str = "class-demo-key",
        easy_mode: bool = True
    ):
        self.chain_id = chain_id
        self.secret_key = secret_key
        self.easy_mode = easy_mode

        self.chain: List[Block] = []
        self.mempool: List[Any] = []

        # Genesis is mined too
        self._create_genesis()

    def add_transaction(self, tx: Any) -> None:
        self.mempool.append(tx)

    def _create_genesis(self) -> None:
        self.mempool.append({"GENESIS": True})
        self.mine_block()

    # ----------------------------
    # TWO dynamic parameters for PoW
    # ----------------------------

    def _dynamic_params(self, height: int, prev_hash: str, tx_count: int) -> Tuple[int, int]:
        seed = int(prev_hash[:8], 16) if prev_hash and prev_hash != ("0" * 64) else 0

        if self.easy_mode:
            difficulty_bits = 10 + ((height + tx_count + (seed & 0xF)) % 5)  # 10..14
            window_mod = 2 + ((height + ((seed >> 4) & 0xFF)) % 5)          # 2..6
        else:
            difficulty_bits = 16 + ((height + tx_count + (seed & 0xF)) % 7)  # 16..22
            window_mod = 3 + ((height + ((seed >> 4) & 0xFF)) % 9)           # 3..11

        return difficulty_bits, window_mod

    # ----------------------------
    # metadata commitments
    # ----------------------------

    def _metadata_hash(
        self,
        height: int,
        ts: float,
        prev_hash: str,
        merkle: str,
        difficulty_bits: int,
        window_mod: int
    ) -> str:
        meta = f"{self.chain_id}|{height}|{ts}|{prev_hash}|{merkle}|{difficulty_bits}|{window_mod}"
        return aurohash_256(meta.encode("utf-8"))

    def _auth_tag(self, metadata_hash: str) -> str:
        msg = (self.secret_key + "|" + metadata_hash).encode("utf-8")
        return aurohash_256(msg)

    # ----------------------------
    # Proof-of-Work core
    # ----------------------------

    def _pow_hash(self, metadata_hash: str, nonce: int, window_mod: int) -> str:
        salt = f"{window_mod}:{(nonce % (window_mod * 997 + 1))}".encode("utf-8")
        payload = metadata_hash.encode("utf-8") + b"|" + str(nonce).encode("utf-8") + b"|" + salt
        return aurohash_256(payload)

    def _meets_difficulty(self, h: str, difficulty_bits: int) -> bool:
        value = int(h, 16)
        return (value >> (256 - difficulty_bits)) == 0

    # ----------------------------
    # Mining a block
    # ----------------------------

    def mine_block(self, max_nonce: int = 500_000, report_every: int = 50_000) -> Block:
        height = len(self.chain)
        ts = time.time()
        prev = self.chain[-1].block_hash if self.chain else "0" * 64
        txs = self.mempool[:]
        self.mempool.clear()

        mk = merkle_root(txs)
        difficulty_bits, window_mod = self._dynamic_params(height, prev, len(txs))
        meta_h = self._metadata_hash(height, ts, prev, mk, difficulty_bits, window_mod)
        tag = self._auth_tag(meta_h)

        nonce = 0
        while True:
            bh = self._pow_hash(meta_h, nonce, window_mod)

            if self._meets_difficulty(bh, difficulty_bits):
                break

            nonce += 1

            if report_every and nonce % report_every == 0:
                print(f"[mining] height={height} nonce={nonce} diff={difficulty_bits} window={window_mod}")

            if nonce >= max_nonce:
                raise RuntimeError(
                    f"Mining exceeded max_nonce={max_nonce}. Lower difficulty or keep easy_mode=True."
                )

        block = Block(
            height=height,
            timestamp=ts,
            prev_hash=prev,
            transactions=txs,
            merkle=mk,
            difficulty_bits=difficulty_bits,
            window_mod=window_mod,
            metadata_hash=meta_h,
            auth_tag=tag,
            nonce=nonce,
            block_hash=bh
        )

        self.chain.append(block)
        return block

    # ----------------------------
    # NEW: Validation (immutability proof)
    # ----------------------------

    def is_valid(self) -> bool:
        """
        Validates:
          - prev_hash linkage
          - merkle root integrity
          - metadata_hash integrity
          - auth_tag integrity
          - PoW integrity (block_hash recomputation + difficulty check)
        """
        for i, b in enumerate(self.chain):
            expected_prev = ("0" * 64) if i == 0 else self.chain[i - 1].block_hash
            if b.prev_hash != expected_prev:
                return False

            if b.merkle != merkle_root(b.transactions):
                return False

            recomputed_meta = self._metadata_hash(
                b.height, b.timestamp, b.prev_hash, b.merkle, b.difficulty_bits, b.window_mod
            )
            if b.metadata_hash != recomputed_meta:
                return False

            if b.auth_tag != self._auth_tag(b.metadata_hash):
                return False

            recomputed_pow = self._pow_hash(b.metadata_hash, b.nonce, b.window_mod)
            if b.block_hash != recomputed_pow:
                return False

            if not self._meets_difficulty(b.block_hash, b.difficulty_bits):
                return False

        return True

    def print_chain(self) -> None:
        for b in self.chain:
            print("\n==================== BLOCK ====================")
            print(f"Height:          {b.height}")
            print(f"Timestamp:       {b.timestamp}")
            print(f"Prev Hash:       {b.prev_hash}")
            print(f"Tx Count:        {len(b.transactions)}")
            print(f"Transactions:    {b.transactions}")
            print(f"Merkle Root:     {b.merkle}")
            print(f"DifficultyBits:  {b.difficulty_bits}")
            print(f"WindowMod:       {b.window_mod}")
            print(f"Metadata Hash:   {b.metadata_hash}")
            print(f"Auth Tag:        {b.auth_tag}")
            print(f"Nonce:           {b.nonce}")
            print(f"Block Hash:      {b.block_hash}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo-tamper", action="store_true", help="tamper with a block to prove immutability")
    args = parser.parse_args()

    bc = Blockchain(easy_mode=True)

    bc.add_transaction({"from": "A", "to": "B", "amount": 10})
    bc.add_transaction({"from": "B", "to": "C", "amount": 5})
    bc.mine_block()

    bc.add_transaction("UserLoginEvent: alice@10.0.0.5")
    bc.add_transaction("FileUploadEvent: report.pdf")
    bc.mine_block()

    bc.print_chain()
    print("\nChain valid?", bc.is_valid())

    if args.demo_tamper:
        print("\n--- TAMPER DEMO ---")
        # Modify block 1 (not genesis) after it was mined
        bc.chain[1].transactions[0] = {"from": "A", "to": "B", "amount": 999999}
        print("Tampered with block 1 transactions.")
        print("Chain valid after tamper?", bc.is_valid())


if __name__ == "__main__":
    main()
