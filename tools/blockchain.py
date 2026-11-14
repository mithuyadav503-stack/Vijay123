"""Blockchain toolkit: Bitcoin address validation (base58check + bech32), raw transaction parsing,
wallet-file security auditing — all offline and educational. No private keys ever leave the device."""

import hashlib
import re
import base64

CHARSET_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


class BlockchainToolkit:
    def __init__(self, security, file_manager=None):
        self.sec = security
        self.fm = file_manager

    # ---------------- base58check ----------------
    @staticmethod
    def _b58decode_check(s):
        n = 0
        for c in s:
            idx = CHARSET_BASE58.find(c)
            if idx < 0:
                return None, f"invalid base58 character '{c}'"
            n = n * 58 + idx
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        pad = 0
        for c in s:
            if c == CHARSET_BASE58[0]:
                pad += 1
            else:
                break
        raw = b"\x00" * pad + raw
        if len(raw) < 5:
            return None, "too short"
        payload, checksum = raw[:-4], raw[-4:]
        if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
            return None, "checksum mismatch (address is mistyped or corrupt)"
        return payload, None

    @staticmethod
    def _b58encode_check(payload):
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        raw = payload + checksum
        n = int.from_bytes(raw, "big")
        out = ""
        while n > 0:
            n, rem = divmod(n, 58)
            out = CHARSET_BASE58[rem] + out
        pad = 0
        for b in raw:
            if b == 0:
                pad += 1
            else:
                break
        return CHARSET_BASE58[0] * pad + out

    # ---------------- bech32 (BIP-173) ----------------
    @staticmethod
    def _bech32_polymod(values):
        gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
        chk = 1
        for v in values:
            b = chk >> 25
            chk = (chk & 0x1FFFFFF) << 5 ^ v
            for i in range(5):
                chk ^= gen[i] if ((b >> i) & 1) else 0
        return chk

    @staticmethod
    def _bech32_hrp_expand(hrp):
        return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]

    @staticmethod
    def _convertbits(data, frombits, tobits, pad=True):
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        for value in data:
            acc = (acc << frombits) | value
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if pad and bits:
            ret.append((acc << (tobits - bits)) & maxv)
        return ret

    def validate_bech32_address(self, addr):
        """Validate a bc1... bech32 address (BIP-173 checksum)."""
        addr = addr.lower()
        if not addr.startswith("bc1"):
            return {"valid": False, "reason": "bech32 addresses start with 'bc1'"}
        pos = addr.rfind("1")
        hrp = addr[:pos]
        data_part = addr[pos + 1:]
        if any(ord(c) < 33 or ord(c) > 126 for c in addr):
            return {"valid": False, "reason": "invalid characters"}
        data = []
        for c in data_part:
            idx = BECH32_CHARSET.find(c)
            if idx < 0:
                return {"valid": False, "reason": f"invalid bech32 character '{c}'"}
            data.append(idx)
        checksum = self._bech32_polymod(self._bech32_hrp_expand(hrp) + data)
        if checksum != 1:
            return {"valid": False, "reason": "bech32 checksum mismatch"}
        witver = data[0]
        prog = self._convertbits(data[1:-6], 5, 8, False)
        lengths = {0: 20, 1: 32}
        if witver not in lengths or len(prog) != lengths[witver]:
            return {"valid": False, "reason": f"invalid witness program length {len(prog)} for version {witver}"}
        fmt = {0: "P2WPKH/P2WSH (SegWit v0)", 1: "Taproot P2TR (SegWit v1)"}
        return {"valid": True, "type": fmt.get(witver, f"witness v{witver}"),
                "witness_version": witver, "program_hex": bytes(prog).hex()}

    def analyze_btc_address(self, address):
        """Full format analysis of a Bitcoin address. Never requires or accepts private keys."""
        address = address.strip()
        result = {"address": address, "valid": False}
        if address.startswith(("bc1", "BC1")):
            verdict = self.validate_bech32_address(address)
            result.update(verdict)
            result["network"] = "mainnet" if address.startswith("bc1") else "mainnet (upper-case bech32)"
            return result
        if len(address) < 26 or len(address) > 35:
            result["reason"] = f"length {len(address)} outside 26-35 range"
            return result
        payload, err = self._b58decode_check(address)
        if err:
            result["reason"] = err
            return result
        version = payload[0]
        h160 = payload[1:]
        if len(h160) != 20:
            result["reason"] = f"payload length {len(h160)}, expected 20"
            return result
        types = {0x00: "P2PKH (pay-to-pubkey-hash, legacy '1...')",
                 0x05: "P2SH (pay-to-script-hash, '3...')",
                 0x6F: "testnet P2PKH ('m/n...')",
                 0xC4: "testnet P2SH ('2...')"}
        result.update({
            "valid": True,
            "type": types.get(version, f"unknown version byte 0x{version:02x}"),
            "network": "mainnet" if version in (0x00, 0x05) else "testnet/signet",
            "version_byte": f"0x{version:02x}",
            "hash160": h160.hex(),
        })
        return result

    # ---------------- raw transaction parsing ----------------
    def parse_raw_tx(self, hex_tx):
        """Parse a raw Bitcoin transaction hex: version, inputs, outputs, locktime."""
        h = hex_tx.strip().lower()
        if not re.fullmatch(r"[0-9a-f]+", h) or len(h) % 2:
            return {"error": "Input is not valid hex."}
        raw = bytes.fromhex(h)
        off = 0

        def read(n):
            nonlocal off
            if off + n > len(raw):
                raise ValueError("transaction truncated")
            b = raw[off:off + n]
            off += n
            return b

        def read_varint():
            first = read(1)[0]
            if first < 0xFD:
                return first
            sizes = {0xFD: 2, 0xFE: 4, 0xFF: 8}
            return int.from_bytes(read(sizes[first]), "little")

        segwit = False
        version = int.from_bytes(read(4), "little")
        marker = raw[off] if off < len(raw) else None
        if marker == 0x00:
            segwit = True
            read(1)
            flag = read(1)[0]
        n_in = read_varint()
        inputs = []
        for _ in range(n_in):
            txid = read(32)[::-1].hex()
            vout = int.from_bytes(read(4), "little")
            script_len = read_varint()
            script_sig = read(script_len).hex()
            sequence = int.from_bytes(read(4), "little")
            inputs.append({"txid": txid, "vout": vout, "script_sig": script_sig[:120], "sequence": sequence})
        n_out = read_varint()
        outputs = []
        for _ in range(n_out):
            value_sat = int.from_bytes(read(8), "little")
            script_len = read_varint()
            script_pub_key = read(script_len).hex()
            outputs.append({"value_btc": value_sat / 1e8, "value_sats": value_sat,
                            "script_pub_key": script_pub_key[:120]})
        witnesses = []
        if segwit:
            for _ in range(n_in):
                n_items = read_varint()
                items = []
                for _ in range(n_items):
                    l = read_varint()
                    items.append(read(l).hex()[:140])
                witnesses.append(items)
        locktime = int.from_bytes(read(4), "little")
        return {
            "txid_format": "double-SHA256 of serialized tx (displayed reversed)",
            "version": version,
            "segwit": segwit,
            "flag": flag if segwit else None,
            "inputs": inputs,
            "outputs": outputs,
            "witnesses": witnesses if segwit else None,
            "locktime": locktime,
            "total_output_btc": sum(o["value_btc"] for o in outputs),
        }

    # ---------------- wallet security audit (local only) ----------------
    def wallet_security_audit(self, path):
        """Audit a local wallet/config file for unsafe practices. Never reads secret file contents."""
        p = self.sec.validate_path(path)
        self.sec.check(1, f"wallet security audit of {p.name}")
        findings = []
        if self.sec.is_secret_file(p):
            findings.append({"level": "INFO", "note": "File matches secret-file patterns; contents were NOT read."})
        else:
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                return {"error": f"Cannot read file: {exc}"}
            if re.search(r"(?i)privkey|private[_-]?key", text) and re.search(r"[A-Fa-f0-9]{64}", text):
                findings.append({"level": "CRITICAL", "note": "Possible raw 64-hex private key near a 'private key' label."})
            if re.search(r"(?i)\b(?:seed|mnemonic)\b", text) and len(re.findall(r"\b[a-z]{3,8}\b", text)) > 12:
                findings.append({"level": "CRITICAL", "note": "Possible seed phrase stored in plaintext."})
            if "wif" in text.lower() or re.search(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{51}\b", text):
                findings.append({"level": "CRITICAL", "note": "Possible WIF-encoded private key present."})
            if re.search(r"(?i)password\s*[=:]\s*['\"]?[^\s'\"]+", text):
                findings.append({"level": "HIGH", "note": "Plaintext password assignment found."})
            if re.search(r"(?i)https?://", text):
                findings.append({"level": "MEDIUM", "note": "File references remote URLs; verify no key material is sent there."})
        if not findings:
            findings.append({"level": "OK", "note": "No obvious insecure patterns detected in this file."})
        return {
            "file": str(p),
            "warning": "This audit is heuristic and local-only. Nothing was uploaded.",
            "findings": findings,
        }

    # ---------------- defensive wallet format detection (local audit only) ----------------
    def detect_wallet_format(self, path):
        """Identify a wallet file's format and report its security posture.

        STRICTLY DEFENSIVE: reports which key material the file *contains* and how well
        it is protected. It never decrypts, extracts, or exports anything.
        """
        p = self.sec.validate_path(path)
        self.sec.check(1, f"wallet format audit of {p.name}")
        head = b""
        try:
            with open(p, "rb") as fh:
                head = fh.read(4096)
        except OSError as exc:
            return {"error": f"Cannot read file: {exc}"}
        text = None
        try:
            text = head.decode("utf-8", errors="strict")
            is_json = text.lstrip().startswith(("{", "["))
        except UnicodeDecodeError:
            is_json = False

        fmt = "unknown"
        encrypted = None
        findings = []

        if head.startswith((b"\x00\x05\x15\xdb", b"\x04\x15\x61\xdb", b"\x09\x05\x15\xdb")):
            fmt = "Bitcoin Core (Berkeley DB)"
            has_mkey = b"mkey" in head
            has_ckey = b"ckey" in head
            has_plain = b"privkey" in head or b"key\x00" in head
            if has_ckey:
                encrypted = True
                findings.append({"level": "OK", "note": "Private keys appear encrypted (ckey records present)."})
            elif has_plain and not has_mkey:
                encrypted = False
                findings.append({"level": "CRITICAL", "note": "No mkey/ckey records found: private keys may be stored UNENCRYPTED."})
            elif has_mkey:
                encrypted = True
                findings.append({"level": "OK", "note": "Encrypted master key (mkey) present."})
            else:
                encrypted = None
                findings.append({"level": "INFO", "note": "First 4KB shows no key records; scan deeper sections manually if needed."})
        elif is_json and '"seed_version"' in text:
            fmt = "Electrum wallet (JSON)"
            encrypted = False
            if '"xprv"' in text or '"xpriv"' in text:
                findings.append({"level": "CRITICAL", "note": "Extended PRIVATE key (xprv) stored in plaintext JSON."})
            if '"seed"' in text:
                findings.append({"level": "CRITICAL", "note": "Seed phrase stored in plaintext JSON."})
            findings.append({"level": "MEDIUM", "note": "Electrum wallets are plaintext JSON by design. Protect the file itself."})
        elif is_json and '"pbkdf2_iterations"' in text and '"payload"' in text:
            fmt = "Blockchain.com wallet (AES JSON)"
            encrypted = True
            import re as _re
            m = _re.search(r'"pbkdf2_iterations"\s*:\s*(\d+)', text)
            iters = int(m.group(1)) if m else 0
            if 0 < iters < 5000:
                findings.append({"level": "HIGH", "note": f"PBKDF2 iterations only {iters} (<5000): passphrase brute-force is far cheaper than modern standards."})
            elif iters:
                findings.append({"level": "OK", "note": f"PBKDF2 iterations: {iters}."})
        elif is_json and ('"kdfparams"' in text or '"cipher"' in text):
            fmt = "Web3 secret storage (MetaMask / Trust Wallet keystore)"
            encrypted = True
            import re as _re
            m = _re.search(r'"n"\s*:\s*(\d+)', text)
            n = int(m.group(1)) if m else 0
            if 0 < n < 16384:
                findings.append({"level": "HIGH", "note": f"scrypt/pbkdf2 N={n} is below the 16384 baseline: weak KDF."})
            elif n:
                findings.append({"level": "OK", "note": f"KDF work factor N={n}."})
        elif b"org.multibit" in head or b"multibit" in head.lower():
            fmt = "MultiBit (.wallet)"
            encrypted = None
            findings.append({"level": "MEDIUM", "note": "MultiBit HD wallets are key-value formats; verify encryption status in the app."})
        elif head[:1] == b"\x9e" or b"armory" in head.lower():
            fmt = "Armory wallet (possibly fragmented)"
            encrypted = None
            findings.append({"level": "INFO", "note": "Armory format detected heuristically; confidence is lower."})
        else:
            findings.append({"level": "INFO", "note": "No known wallet signature in the first 4KB."})

        import os as _os
        mode = _os.stat(p).st_mode & 0o777
        if mode & 0o077:
            findings.append({"level": "HIGH", "note": f"File permissions {oct(mode)[-3:]}: readable by other users. Run: chmod 600 {p.name}"})
        else:
            findings.append({"level": "OK", "note": f"File permissions {oct(mode)[-3:]}: restricted."})

        return {
            "file": str(p),
            "format": fmt,
            "encrypted": encrypted,
            "encrypted_meaning": {True: "key material is encrypted", False: "PLAINTEXT key material present",
                                  None: "unknown"}.get(encrypted),
            "findings": findings,
            "disclaimer": "Defensive audit only: file contents were scanned for structure markers. "
                          "Nothing was decrypted, extracted, or transmitted.",
        }
