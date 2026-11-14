"""Cryptography toolkit: hashes, HMAC, AES, RSA, Ed25519 — all local, defensive/educational.

Rules enforced here:
- Private keys and seed phrases are NEVER returned to the LLM or written to logs.
- Private keys are only ever printed once, at generation time, with a warning.
"""

import base64
import hashlib
import hmac as hmac_mod
import os
import secrets

from core.security import PermissionDenied

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes as cz_hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

HASH_ALGOS = {
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}


class CryptoToolkit:
    def __init__(self, security):
        self.sec = security

    # ---------------- hashes ----------------
    def hash_text(self, text, algo="sha256"):
        algo = algo.lower().replace("-", "_")
        if algo not in HASH_ALGOS:
            raise ValueError(f"Unsupported hash algorithm '{algo}'. Supported: {', '.join(sorted(HASH_ALGOS))}")
        digest = HASH_ALGOS[algo](text.encode("utf-8")).hexdigest()
        self.sec.log("CRYPTO", f"hash {algo} of {len(text)} chars of input")
        return {"algorithm": algo, "input_length": len(text), "digest": digest}

    def hash_file(self, path, algo="sha256"):
        algo = algo.lower().replace("-", "_")
        if algo not in HASH_ALGOS:
            raise ValueError(f"Unsupported hash algorithm '{algo}'.")
        p = self.sec.validate_path(path)
        h = HASH_ALGOS[algo]()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return {"algorithm": algo, "file": str(p), "size": p.stat().st_size, "digest": h.hexdigest()}

    def hmac_compute(self, key, message, algo="sha256"):
        algo = algo.lower().replace("-", "_")
        if algo not in HASH_ALGOS:
            raise ValueError(f"Unsupported HMAC algorithm '{algo}'.")
        digest = hmac_mod.new(key.encode("utf-8"), message.encode("utf-8"), HASH_ALGOS[algo]).hexdigest()
        return {"algorithm": f"HMAC-{algo}", "digest": digest}

    # ---------------- AES (password-based, AES-256-GCM) ----------------
    def _derive_key(self, password, salt):
        if not HAVE_CRYPTOGRAPHY:
            raise PermissionDenied(
                "AES requires the 'cryptography' package. Install it with: pip install cryptography"
            )
        kdf = PBKDF2HMAC(algorithm=cz_hashes.SHA256(), length=32, salt=salt, iterations=200_000)
        return kdf.derive(password.encode("utf-8"))

    def aes_encrypt(self, plaintext, password):
        """AES-256-GCM with PBKDF2 key derivation. Output: base64(salt|nonce|ciphertext)."""
        if not HAVE_CRYPTOGRAPHY:
            raise PermissionDenied("AES requires the 'cryptography' package (pip install cryptography).")
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(password, salt)
        ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
        blob = base64.b64encode(salt + nonce + ct).decode()
        self.sec.log("CRYPTO", "AES-256-GCM encrypt (password-based)")
        return {"scheme": "AES-256-GCM + PBKDF2-SHA256 (200k iters)", "ciphertext_b64": blob}

    def aes_decrypt(self, blob_b64, password):
        if not HAVE_CRYPTOGRAPHY:
            raise PermissionDenied("AES requires the 'cryptography' package (pip install cryptography).")
        try:
            raw = base64.b64decode(blob_b64)
            salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
            key = self._derive_key(password, salt)
            pt = AESGCM(key).decrypt(nonce, ct, None)
            return {"plaintext": pt.decode("utf-8")}
        except Exception:
            raise PermissionDenied("Decryption failed: wrong password or corrupted ciphertext.")

    # ---------------- RSA ----------------
    def rsa_generate(self, bits=2048):
        if not HAVE_CRYPTOGRAPHY:
            raise PermissionDenied("RSA requires the 'cryptography' package.")
        if bits < 2048:
            raise ValueError("RSA key size must be at least 2048 bits.")
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        priv_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        pub_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        self.sec.log("CRYPTO", f"RSA-{bits} keypair generated")
        return {
            "warning": "PRIVATE KEY: store safely, never share, never send to any AI or server.",
            "private_key_pem": priv_pem,
            "public_key_pem": pub_pem,
        }

    def rsa_sign(self, private_key_pem, message):
        if not HAVE_CRYPTOGRAPHY:
            raise PermissionDenied("RSA requires the 'cryptography' package.")
        key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        sig = key.sign(
            message.encode(),
            padding.PSS(mgf=padding.MGF1(cz_hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            cz_hashes.SHA256(),
        )
        return {"signature_b64": base64.b64encode(sig).decode(), "scheme": "RSA-PSS + SHA256"}

    def rsa_verify(self, public_key_pem, message, signature_b64):
        if not HAVE_CRYPTOGRAPHY:
            raise PermissionDenied("RSA requires the 'cryptography' package.")
        key = serialization.load_pem_public_key(public_key_pem.encode())
        try:
            key.verify(base64.b64decode(signature_b64), message.encode(),
                       padding.PSS(mgf=padding.MGF1(cz_hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                       cz_hashes.SHA256())
            return {"valid": True}
        except InvalidSignature:
            return {"valid": False}

    # ---------------- Ed25519 ----------------
    def ed25519_generate(self):
        if not HAVE_CRYPTOGRAPHY:
            raise PermissionDenied("Ed25519 requires the 'cryptography' package.")
        key = ed25519.Ed25519PrivateKey.generate()
        priv_bytes = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        pub_bytes = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.sec.log("CRYPTO", "Ed25519 keypair generated")
        return {
            "warning": "PRIVATE KEY: store safely, never share, never send to any AI or server.",
            "private_key_hex": priv_bytes.hex(),
            "public_key_hex": pub_bytes.hex(),
        }

    def ed25519_sign(self, private_key_hex, message):
        if not HAVE_CRYPTOGRAPHY:
            raise PermissionDenied("Ed25519 requires the 'cryptography' package.")
        key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
        sig = key.sign(message.encode())
        return {"signature_hex": sig.hex(), "scheme": "Ed25519"}

    def ed25519_verify(self, public_key_hex, message, signature_hex):
        if not HAVE_CRYPTOGRAPHY:
            raise PermissionDenied("Ed25519 requires the 'cryptography' package.")
        key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        try:
            key.verify(bytes.fromhex(signature_hex), message.encode())
            return {"valid": True}
        except InvalidSignature:
            return {"valid": False}

    # ---------------- helpers ----------------
    def random_hex(self, nbytes=32):
        return {"bytes": nbytes, "hex": secrets.token_hex(nbytes)}

    def password_strength_note(self, password):
        """Local, defensive assessment. The password is never stored or transmitted."""
        notes = []
        if len(password) < 12:
            notes.append("Too short: use at least 12 characters.")
        if password.islower() or password.isupper():
            notes.append("Use mixed upper and lower case.")
        if not any(c.isdigit() for c in password):
            notes.append("Add digits.")
        if not any(not c.isalnum() for c in password):
            notes.append("Add symbols.")
        if not notes:
            notes.append("Good length and character mix. Still: never reuse passwords across services.")
        return {"length": len(password), "notes": notes}
