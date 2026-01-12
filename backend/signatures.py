class SignatureStore:
    def __init__(self):
        self.store = {}
    def add(self, sig_id, pattern, metadata):
        self.store[sig_id] = {"pattern": pattern, "meta": metadata}
    def match_hash(self, sha256):
        for sid, s in self.store.items():
            if s["pattern"].get("file_hash") == sha256:
                return sid, s["meta"]
        return None, None
