# BlockChain (Single-Node Educational Blockchain)

This project implements a **local (non-distributed) blockchain** for coursework under strict constraints:

- **No SHA-256** (custom hash function)
- **Proof-of-Work depends on TWO dynamic parameters**
- **Blocks contain attack-resilient metadata**
- Must justify design choices and provide tradeoffs
- No peer-to-peer network required (single process is fine)

---

## How to Run

### Run normally (mine blocks and print chain)
```bash
python main.py
