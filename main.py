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

def main():
    # TODO: implement Blockchain and run demo
    pass

if __name__ == "__main__":
    main()
from dataclasses import dataclass
from typing import Any, List

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
