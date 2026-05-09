import hashlib
import json
import os
from datetime import datetime, timezone

CHAIN_FILE = "blockchain.json"

class Block:
    def __init__(self, index, filename, file_hash, cert_fingerprint,
                 email, signature, parent_hash=None, previous_hash="0"*64):
        self.index = index
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.filename = filename
        self.file_hash = file_hash
        self.cert_fingerprint = cert_fingerprint
        self.email = email
        self.signature = signature
        self.parent_hash = parent_hash
        self.previous_hash = previous_hash
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "filename": self.filename,
            "file_hash": self.file_hash,
            "cert_fingerprint": self.cert_fingerprint,
            "email": self.email,
            "signature": self.signature,
            "parent_hash": self.parent_hash,
            "previous_hash": self.previous_hash
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "filename": self.filename,
            "file_hash": self.file_hash,
            "cert_fingerprint": self.cert_fingerprint,
            "email": self.email,
            "signature": self.signature,
            "parent_hash": self.parent_hash,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }


class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_chain()
        if len(self.chain) == 0:
            self._create_genesis_block()

    def _create_genesis_block(self):
        genesis = Block(
            index=0,
            filename="GENESIS",
            file_hash="0"*64,
            cert_fingerprint="GENESIS",
            email="system@genesis",
            signature="GENESIS",
            previous_hash="0"*64
        )
        self.chain.append(genesis)
        self.save_chain()

    def add_block(self, filename, file_hash, cert_fingerprint,
                  email, signature, parent_hash=None):
        last_block = self.chain[-1]
        new_block = Block(
            index=len(self.chain),
            filename=filename,
            file_hash=file_hash,
            cert_fingerprint=cert_fingerprint,
            email=email,
            signature=signature,
            parent_hash=parent_hash,
            previous_hash=last_block.hash
        )
        self.chain.append(new_block)
        self.save_chain()
        return new_block

    def query_by_hash(self, file_hash):
        for block in reversed(self.chain):
            if block.file_hash == file_hash:
                return block
        return None

    def query_by_filename(self, filename):
        return [b for b in self.chain if b.filename == filename]

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.hash != current.compute_hash():
                return False
            if current.previous_hash != previous.hash:
                return False
        return True

    def save_chain(self):
        with open(CHAIN_FILE, "w") as f:
            json.dump([b.to_dict() for b in self.chain], f, indent=2)

    def load_chain(self):
        if not os.path.exists(CHAIN_FILE):
            return
        with open(CHAIN_FILE, "r") as f:
            data = json.load(f)
        self.chain = []
        for d in data:
            b = Block.__new__(Block)
            b.index = d["index"]
            b.timestamp = d["timestamp"]
            b.filename = d["filename"]
            b.file_hash = d["file_hash"]
            b.cert_fingerprint = d["cert_fingerprint"]
            b.email = d["email"]
            b.signature = d["signature"]
            b.parent_hash = d["parent_hash"]
            b.previous_hash = d["previous_hash"]
            b.hash = d["hash"]
            self.chain.append(b)
