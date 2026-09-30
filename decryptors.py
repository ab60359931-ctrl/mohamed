# ============================================================
# decryptors.py - كل دوال فك التشفير (قديم + جديد)
# ============================================================
import os, re, json, base64, struct, gzip, pickle, contextlib, hashlib, hmac, ctypes, io
from typing import Optional, Dict, Any, Union, List, Tuple

from Crypto.Cipher import AES, ChaCha20, ChaCha20_Poly1305
from Crypto.Util.Padding import unpad

try:
    import msgpack
    MSGPACK_AVAILABLE = True
except ImportError:
    MSGPACK_AVAILABLE = False

try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

# ============================================================
# 1) DARK TUNNEL
# ============================================================
class DTConstants:
    KEY_256 = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"
    KEY_192 = b"F)J@NcRfUjXn2r4u7x!A%D*G"
    IV = bytes.fromhex("232e39185523184a5723586242200e05")


class DTDecryptor:
    @staticmethod
    def _b64(s):
        s = s.replace("-", "+").replace("_", "/")
        if pad := len(s) % 4:
            s += "=" * (4 - pad)
        return base64.b64decode(s)

    @staticmethod
    def _aes_cfb(data, key, iv):
        return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(data)

    @classmethod
    def execute(cls, file_bytes):
        if not MSGPACK_AVAILABLE:
            return None
        with contextlib.suppress(Exception):
            raw = file_bytes.decode('utf-8', errors='ignore').strip()
            if not raw:
                return None
            if "://" in raw:
                raw = raw.split("://", 1)[1]
            outer = json.loads(cls._b64(raw).decode("utf-8"))
            if "encryptedLockedConfig" not in outer:
                return None
            enc = cls._b64(outer["encryptedLockedConfig"])
            dec = cls._aes_cfb(enc, DTConstants.KEY_256, DTConstants.IV)
            unpacked = msgpack.unpackb(dec, raw=False, strict_map_key=False)
            if "EncryptedLockedConfig" in unpacked:
                dec2 = cls._aes_cfb(unpacked["EncryptedLockedConfig"], DTConstants.KEY_192, DTConstants.IV)
                unpacked2 = msgpack.unpackb(dec2, raw=False, strict_map_key=False)
                unpacked["EncryptedLockedConfig"] = unpacked2
            outer["encryptedLockedConfig"] = unpacked
            return json.dumps(outer, indent=4, ensure_ascii=False, default=str)
        return None


# ============================================================
# 2) HTTP CUSTOM - V1 (القديم)
# ============================================================
class HCConstantsV1:
    CHACHA_KEYS = [
        bytes.fromhex("2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d"),
        bytes.fromhex("3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372"),
        bytes.fromhex("cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3"),
        bytes.fromhex("4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193"),
        bytes.fromhex("f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63"),
        bytes.fromhex("81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c"),
        bytes.fromhex("45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944"),
        bytes.fromhex("3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea")
    ]
    RST_KEYS = [b"JN1k3YHc2.6_v235", b"JN1k3YHc_2.7_v71", b"JN1k3YHc2.7.ps69",
                b"JN1k3YHc2.7.6950", b"Jn1K3yHc2.8.ps08", b"Jn1K3yHc2.9.ps6c",
                b"Zk:L7>WKaiK*s9>D", b"!<f!&WIlM**R.B0X", b"b4a5opinx2uloec6"]
    JKL_KEY_OLD = bytes([0xd5, 0xd4, 0xd3, 0xd2, 0xd1, 0xd0, 0xcf, 0xce, 0xcd, 0xcc,
                         0xbd, 0xbc, 0xbb, 0xba, 0xb9, 0xb8, 0xb7, 0xb6, 0xb5, 0xb4])
    JKL_KEY_NEW = bytes([8, 9, 10, 11, 12, 13, 14, 15, 17, 17, 5, 4, 3, 2, 1, 0, 255, 254, 253, 252])
    TOKEN_MAP = {
        0: "payload", 1: "proxy", 2: "lockAllConfig", 3: "blockedByRoot",
        4: "expiryTime", 5: "noteEnabled", 6: "notes", 7: "sshField",
        8: "mobileDataAndLockProvider", 9: "unlockUserAndPass", 10: "ovpnConfig",
        11: "ovpnUserAndPass", 12: "sni", 13: "unlockUserAndPass2", 14: "unknown14",
        15: "blockedByHwid", 16: "cloudconfig", 17: "psiphon", 18: "name",
        19: "blockArea", 20: "connectionMode", 21: "blockedByPassword",
        22: "unknown22", 23: "extraSniffer", 24: "psiphon2", 25: "v2rayEnabled",
        26: "v2rayConfig", 27: "version", 28: "slowdnsEnabled", 29: "slowdnsServer",
        30: "slowdnsPublickey", 31: "dnsResolver"
    }
    BRAILLE = "⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵⠼⠁⠼⠃⠼⠉⠼⠙⠼⠑⠼⠋⠼⠛⠼⠓⠼⠊⠼⠚"
    STATIC_NONCE = b'\xdb' * 8
    RST_XOR_KEY = bytes(range(2, 22))


class HCDecryptorV1:
    @staticmethod
    def _clean_hex(s):
        if not s:
            return ""
        c = re.sub(r'[^0-9a-fA-F]', '', s)
        return f"0{c}" if len(c) % 2 else c

    @staticmethod
    def _is_hex(s):
        return bool(s and len(s) >= 16 and re.fullmatch(r'^[0-9a-fA-F]+$', s))

    @staticmethod
    def _printable(s, strict=False):
        if not s:
            return False
        if len(s) < 4:
            return True
        cnt = sum(1 for c in s if c.isprintable() or c in '\t\n\r')
        return (cnt / len(s)) > (0.90 if strict else 0.80)

    @staticmethod
    def _z3a(data, iv):
        if not data:
            return ""
        out = bytearray()
        for m in re.finditer(r'(-?\d+)\.(-?\d+)', data):
            v1, v2 = int(m.group(1)) - iv, int(m.group(2)) - iv
            with contextlib.suppress(Exception):
                if (d := 1 << v2) != 0:
                    out.append((v1 // d) % 256)
        return out.decode('utf-8', errors='ignore')

    @staticmethod
    def _braille(ct):
        try:
            return bytes(
                (HCConstantsV1.BRAILLE.index(ct[i]) * 16 +
                 HCConstantsV1.BRAILLE.index(ct[i + 1])) & 255
                for i in range(0, len(ct) - 1, 2)
            ).decode('utf-8')
        except ValueError:
            return ct

    @classmethod
    def _creds(cls, val, is_ssh=False):
        if not val:
            return val
        if is_ssh and val[0] in HCConstantsV1.BRAILLE:
            val = cls._braille(val)
        pat = r'^([\w\.-]+):([\d\-]+)@(.+):(.+)$' if is_ssh else r'^([^:]+):(.+)$'
        if m := re.match(pat, val):
            g = m.groups()
            u_enc, p_enc = g[-2:]
            u = cls._z3a(u_enc, len(re.findall(r'(-?\d+)\.(-?\d+)', u_enc)))
            p = cls._z3a(p_enc, len(re.findall(r'(-?\d+)\.(-?\d+)', p_enc)))
            fu, fp = u or u_enc, p or p_enc
            return f"{g[0]}:{g[1]}@{fu}:{fp}" if is_ssh else f"{fu}:{fp}"
        return val

    @classmethod
    def _abc(cls, raw, key, nonce=HCConstantsV1.STATIC_NONCE):
        if not raw:
            return ""
        with contextlib.suppress(Exception):
            data = bytes.fromhex(cls._clean_hex(raw))
            if len(data) > 16:
                c = ChaCha20.new(key=key, nonce=nonce)
                c.seek(64)
                return c.decrypt(data[:-16]).decode('utf-8', errors='ignore')
        return ""

    @classmethod
    def _rst(cls, enc):
        with contextlib.suppress(Exception):
            b64 = bytes(b ^ HCConstantsV1.RST_XOR_KEY[i % 20] for i, b in enumerate(enc.encode('utf-8')))
            aes_ct = base64.b64decode(b64)
            for k in HCConstantsV1.RST_KEYS:
                with contextlib.suppress(Exception):
                    d = unpad(AES.new(k, AES.MODE_ECB).decrypt(aes_ct), AES.block_size)
                    s = d.decode('utf-8', errors='ignore')
                    if "[splitConfig]" in s:
                        return s
        return None

    @classmethod
    def _jkl(cls, s, is_new=False):
        if not s:
            return s
        k = HCConstantsV1.JKL_KEY_NEW if is_new else HCConstantsV1.JKL_KEY_OLD
        with contextlib.suppress(Exception):
            pad = len(s) % 4
            ps = s + "=" * (4 - pad) if pad else s
            d = bytearray(base64.b64decode(ps, validate=True))
            for i, b in enumerate(d):
                kk = k[i % 20]
                d[i] = (((b ^ 0xff) & 0xca) | (b & 0x35)) ^ (((kk ^ 0xff) & 0xca) | (kk & 0x35))
            return base64.b64decode(d.decode('utf-8'), validate=True).decode('utf-8')
        return s

    @classmethod
    def _field(cls, token, nonce):
        if not token or token in {"true", "false", "lifeTime", "[splitPsiphon][splitPsiphon]"} or token.startswith("<"):
            return token
        cands = []
        if cls._is_hex(h := cls._clean_hex(token)) and len(h) >= 32:
            with contextlib.suppress(Exception):
                cands.append(bytes.fromhex(h))
        if len(token) > 16:
            with contextlib.suppress(Exception):
                cands.append(token.encode('latin-1'))
            with contextlib.suppress(Exception):
                cands.append(token.encode('utf-8'))
        for data in dict.fromkeys(c for c in cands if len(c) > 16):
            ct = data[:-16]
            for ck in HCConstantsV1.CHACHA_KEYS:
                with contextlib.suppress(Exception):
                    c = ChaCha20.new(key=ck, nonce=nonce)
                    c.seek(64)
                    dec = c.decrypt(ct).decode('utf-8', errors='ignore')
                    for n in (True, False):
                        if (o := cls._jkl(dec, n)) and o != dec and cls._printable(o):
                            return o
                    if cls._printable(dec, strict=True) and any(x in dec for x in ("HTTP", "@", ":", "{")) or dec.isalnum():
                        return dec
        for n in (True, False):
            if (o := cls._jkl(token, n)) != token and cls._printable(o):
                return o
        return token

    @staticmethod
    def _extract(file_bytes, hex_key):
        with contextlib.suppress(Exception):
            kb = bytes.fromhex(hex_key)
            kl = len(kb)
            try:
                ed = file_bytes.decode('utf-8', errors='ignore').encode('latin-1', errors='ignore')
            except Exception:
                ed = file_bytes
            return bytes(b ^ kb[i % kl] for i, b in enumerate(ed)).decode('utf-8')
        return None

    @classmethod
    def execute(cls, file_bytes):
        if not file_bytes:
            return None
        hp = cls._extract(file_bytes, "e382e4b8adc386f09f9293")
        if not hp:
            return None
        with contextlib.suppress(Exception):
            outer = cls._abc(hp, HCConstantsV1.CHACHA_KEYS[5])
            if not outer or not outer.startswith("{"):
                return None
            jo = json.loads(outer)
            if not isinstance(jo, dict):
                return None
            cfg = jo.get("cfg", {})
            new_fmt = isinstance(cfg, dict) and "content" in cfg
            meta, prot = {}, {}
            if new_fmt:
                for k, n in {'b': 'hwid', 'f': 'area'}.items():
                    if v := str(jo.get(k) or cfg.get(k) or ""):
                        meta[n] = prot[n] = v
                tc, sd = cfg.get('content'), "[splitConfig]"
            else:
                oa = jo.get('a') if isinstance(jo.get('a'), dict) else {}
                for k, n in {'bb': 'hwid', 'e': 'password', 'fe': 'area', 'ed': 'provider'}.items():
                    if v := (jo.get(k) if k == 'e' else oa.get(k)):
                        if dv := cls._abc(str(v), HCConstantsV1.CHACHA_KEYS[7]):
                            meta[n] = prot[n] = dv
                tc, sd = jo.get('xy') or oa.get('xy'), jo.get('uv') or oa.get('uv')
            if not tc or not sd:
                return None
            th = lambda s: s.encode().hex() if s else ""
            h, p, pr, a = meta.get('hwid'), meta.get('password'), meta.get('provider'), meta.get('area')
            dh = (th(h) * 2) if h and not any((p, pr, a)) else (th(p) + th(h) + th(pr) + th(a))
            nonce = bytearray(HCConstantsV1.STATIC_NONCE)
            if dh:
                with contextlib.suppress(Exception):
                    for i, b in enumerate(bytes.fromhex(dh)[:8]):
                        nonce[i] = b
            xy = None
            if new_fmt:
                xy = cls._rst(str(tc))
                if not xy:
                    for k in HCConstantsV1.CHACHA_KEYS:
                        if (t := cls._abc(str(tc), k)) and sd in t:
                            xy = t
                            break
            else:
                xy = cls._abc(str(tc), HCConstantsV1.CHACHA_KEYS[1])
            if not xy:
                return None
            cd = {}
            for i, tok in enumerate(xy.split(str(sd))):
                if i in {22, 24}:
                    continue
                lb = HCConstantsV1.TOKEN_MAP.get(i, f"field_{i}")
                fo = tok
                if new_fmt:
                    fo = cls._field(tok, nonce)
                else:
                    if cls._is_hex(tok):
                        fo = cls._abc(tok, HCConstantsV1.CHACHA_KEYS[7], nonce)
                    fo = cls._jkl(fo, is_new=False)
                if i == 7:
                    fo = cls._creds(fo, is_ssh=True)
                elif i == 11:
                    fo = cls._creds(fo, is_ssh=False)
                if fo:
                    if isinstance(fo, str):
                        fo = fo.replace("88a05e8772eac3e5703e0cd26c6e6f23de72fb09f7ee5a43283d1681f19d", "")
                        with contextlib.suppress(Exception):
                            if fo.startswith(("{", "[")):
                                fo = json.loads(fo)
                    if not (isinstance(fo, str) and cls._is_hex(fo)):
                        cd[lb] = fo
            return json.dumps({"Protections": prot, "Config": cd}, indent=4, ensure_ascii=False, default=str)
        return None


# ============================================================
# 3) HTTP CUSTOM - V2 (الجديد - ToprakHook)
# ============================================================
PKG = b"xyz.easypro.httpcustom"
OUTER_AAD = b"HCX1|xyz.easypro.httpcustom|1"
OUTER_SEED = b"hc-envelope-seal-v1 xyz.easypro.httpcustom"
OUTER_SALT = b"hc-envelope-seal-salt-v1"
OUTER_INFO = b"hc-envelope-seal-info-v1"
OUTER_KEY_V3 = bytes.fromhex("88702df6ae8c089c9478b8cd2bd3f30961b3574a58063d024bdc50f6b779e26f")
N7_HMAC_KEY = bytes.fromhex("9ba7ff3baf33db7aad807a86574b7ca55bef2f048ead51f3a1fe0cff389db3b3")
C0_PREFIX = bytes.fromhex(
    "95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc181"
    "38cabb40b2f81a5a30b11a97cbcf0fed755aa8c2b5495e9bc0c1902077a4cd92"
)


class HCError(ValueError):
    pass


def _c0(d):
    return hashlib.sha256(C0_PREFIX + d).digest()


def _hkdf(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, prev, ctr = b"", b"", 1
    while len(out) < length:
        prev = hmac.new(prk, prev + info + bytes([ctr]), hashlib.sha256).digest()
        out += prev
        ctr += 1
    return out[:length]


def _rol(v, b):
    return ((v << b) & 0xFFFFFFFF) | (v >> (32 - b))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rol(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rol(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rol(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rol(s[b] ^ s[c], 7)


def _rounds(s):
    for _ in range(10):
        _qr(s, 0, 4, 8, 12); _qr(s, 1, 5, 9, 13); _qr(s, 2, 6, 10, 14); _qr(s, 3, 7, 11, 15)
        _qr(s, 0, 5, 10, 15); _qr(s, 1, 6, 11, 12); _qr(s, 2, 7, 8, 13); _qr(s, 3, 4, 9, 14)


def _hchacha20(key, n16):
    s = list(struct.unpack("<4I", b"expand 32-byte k") + struct.unpack("<8I", key) + struct.unpack("<4I", n16))
    _rounds(s)
    return struct.pack("<8I", s[0], s[1], s[2], s[3], s[12], s[13], s[14], s[15])


def _chacha_block(key, n12, ctr):
    init = list(struct.unpack("<4I", b"expand 32-byte k") + struct.unpack("<8I", key) + (ctr & 0xFFFFFFFF,) + struct.unpack("<3I", n12))
    s = init.copy()
    _rounds(s)
    return struct.pack("<16I", *((s[i] + init[i]) & 0xFFFFFFFF for i in range(16)))


def _stream_xor(data, key, n12, ctr=1):
    out = bytearray(len(data))
    for bn, off in enumerate(range(0, len(data), 64)):
        st = _chacha_block(key, n12, ctr + bn)
        for i, v in enumerate(data[off:off + 64]):
            out[off + i] = v ^ st[i]
    return bytes(out)


def _poly1305(msg, otk):
    r = int.from_bytes(otk[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    pad = int.from_bytes(otk[16:], "little")
    acc = 0
    mod = (1 << 130) - 5
    for off in range(0, len(msg), 16):
        acc = ((acc + int.from_bytes(msg[off:off + 16] + b"\x01", "little")) * r) % mod
    return ((acc + pad) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(d):
    return b"" if len(d) % 16 == 0 else b"\x00" * (16 - len(d) % 16)


def _xdec_pure(key, nonce, aad, ct_tag):
    sub = _hchacha20(key, nonce[:16])
    n12 = b"\x00\x00\x00\x00" + nonce[16:]
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    otk = _chacha_block(sub, n12, 0)[:32]
    mac = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct))
    if not hmac.compare_digest(_poly1305(mac, otk), tag):
        raise HCError("XChaCha20-Poly1305 auth failed")
    return _stream_xor(ct, sub, n12, 1)


def _xdec(key, nonce, aad, ct_tag):
    if len(key) != 32 or len(nonce) != 24 or len(ct_tag) < 16:
        raise HCError("bad XChaCha20 input")
    try:
        c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        c.update(aad)
        return c.decrypt_and_verify(ct_tag[:-16], ct_tag[-16:])
    except ValueError:
        raise HCError("XChaCha20-Poly1305 auth failed")
    except Exception:
        return _xdec_pure(key, nonce, aad, ct_tag)


def _argon2id(pw, salt, ops, mem, length=32):
    if len(salt) != 16:
        raise HCError("Argon2 salt must be 16 bytes")
    try:
        from argon2.low_level import Type, hash_secret_raw
        return hash_secret_raw(pw, salt, time_cost=ops, memory_cost=mem // 1024,
                               parallelism=1, hash_len=length, type=Type.ID, version=19)
    except ImportError:
        pass
    raise RuntimeError("Argon2 library required: pip install argon2-cffi")


def _outer_key():
    return _hkdf(_c0(OUTER_SEED), OUTER_SALT, OUTER_INFO)


def _carriers(data):
    seen, cur = set(), data
    for _ in range(6):
        if cur in seen:
            break
        seen.add(cur)
        if len(cur) >= 40:
            yield cur
        try:
            text = cur.decode("utf-8")
        except UnicodeDecodeError:
            break
        if not all(ord(c) <= 0xFF for c in text):
            break
        nxt = bytes(ord(c) for c in text)
        if nxt == cur:
            break
        cur = nxt


def _open_outer(data):
    key = _outer_key()
    last_err = None
    for logical in _carriers(data):
        if len(logical) < 40:
            continue
        try:
            pt = _xdec(key, logical[:24], OUTER_AAD, logical[24:])
            v = json.loads(pt.decode("utf-8"))
            if isinstance(v, dict):
                return v
        except (HCError, UnicodeDecodeError, json.JSONDecodeError) as e:
            last_err = e
        try:
            nonce, ct = logical[:24], logical[24:-16]
            sub = _hchacha20(OUTER_KEY_V3, nonce[:16])
            n12 = b"\x00\x00\x00\x00" + nonce[16:]
            pt = _stream_xor(ct, sub, n12, 1)
            v = json.loads(pt.decode("utf-8"))
            if isinstance(v, dict) and v.get("a") == "HCCFG":
                return v
        except (HCError, UnicodeDecodeError, json.JSONDecodeError) as e:
            last_err = e
    raise HCError("Not valid HTTP Custom envelope") from last_err


def _validate(env):
    if env.get("a") != "HCCFG":
        raise HCError(f"Bad magic: {env.get('a')!r}")
    schema = int(env.get("b", 0))
    if schema == 1:
        ec, ek = "XCHACHA20P1305", "NATIVE-HKDF-SHA256"
    elif schema in (2, 5, 7):
        ec, ek = "s1", "h1"
    else:
        raise HCError(f"Unsupported schema b={schema}")
    if env.get("c") != ec:
        raise HCError(f"Bad cipher: {env.get('c')!r}")
    if env.get("d") != ek:
        raise HCError(f"Bad KDF: {env.get('d')!r}")
    if env.get("e") not in ("n1", "n2", "n7", "n8"):
        raise HCError(f"Bad schedule: {env.get('e')!r}")
    return schema


def _features(env):
    f = env.get("f")
    if not isinstance(f, list) or not all(isinstance(x, str) for x in f):
        raise HCError("Bad features")
    return ",".join(f).encode()


def _n_bytes(env):
    n = env.get("n")
    if n is None or isinstance(n, bool):
        return None
    ni = int(n)
    if str(ni) != str(n):
        raise HCError("Bad n value")
    return str(ni).encode()


def _norm_hwid(hwid):
    v = hwid.strip()
    if len(v) != 32:
        raise HCError("HWID 32 chars required")
    if any(c not in "0123456789abcdefABCDEFhH" for c in v):
        raise HCError("HWID invalid chars")
    return v.upper().encode()


def _env_key(env):
    try:
        k = bytes.fromhex(env["g"])
    except (KeyError, TypeError, ValueError):
        raise HCError("Bad inner key")
    if len(k) != 32:
        raise HCError("Inner key 32 bytes required")
    return k


def _pw_kdf(env, password, ekey):
    kdf = env.get("k")
    if kdf not in ("ARGON2ID13", "a1"):
        raise HCError(f"Bad pw KDF: {kdf!r}")
    try:
        ops, mem = int(env["l"]), int(env["m"])
    except (KeyError, TypeError, ValueError):
        raise HCError("Bad Argon2 params")
    pk = _argon2id(password.encode(), ekey[:16], ops, mem)
    return pk, b"|1|ARGON2ID13|" + str(ops).encode() + b"|" + str(mem).encode()


def _h_flag(env):
    return bool(env.get("h", 0))


def _transcript(env, ekey, hwid_b=None, n7=False):
    feats = _features(env)
    nb = _n_bytes(env)
    vb = b"1"
    t = b"HCCFG\x00" + PKG + b"\x00" + vb + b"\x00" + feats + b"\x00"
    if nb:
        t += nb + b"\x00"
    if hwid_b is not None:
        t += b"hwid\x00" + hwid_b + b"\x00"
    t += ekey
    if n7:
        return hmac.new(N7_HMAC_KEY, b"\xd3" + C0_PREFIX[:32] + t, hashlib.sha256).digest()
    return _c0(t)


def _derive(env, password, hwid):
    sched = env.get("e")
    schema = _validate(env)
    ekey = _env_key(env)
    feats = _features(env)
    nb = _n_bytes(env)
    vb = b"1"
    is_hwid = sched in ("n2", "n8")
    is_n7 = sched in ("n7", "n8")

    if is_hwid and hwid is None:
        cnt = len(env.get("o", [])) if isinstance(env.get("o"), list) else 0
        raise HCError(f"HWID_REQUIRED:{cnt}")

    hwid_b = _norm_hwid(hwid) if is_hwid else None
    ikm = _transcript(env, ekey, hwid_b, n7=is_n7)
    protected = _h_flag(env)
    aad_prot = b"|0"

    if protected:
        if password is None:
            raise HCError("HWID_PASSWORD_REQUIRED" if is_hwid else "PASSWORD_REQUIRED")
        pk, aad_prot = _pw_kdf(env, password, ekey)
        ikm = ikm + pk

    sched_b = sched.encode()
    info = b"app-config|" + sched_b + b"|" + PKG + b"|" + vb + b"|" + feats
    if nb:
        info += b"|" + nb
    if hwid_b:
        info += b"|hwid|" + hwid_b
    skey = _hkdf(ikm, ekey, info)

    aad = (b"HCCFG|" + str(schema).encode() + b"|XCHACHA20P1305|NATIVE-HKDF-SHA256|" +
           sched_b + b"|" + PKG + b"|" + vb + b"|" + feats + aad_prot)
    if nb:
        aad += b"|" + nb

    if is_hwid:
        slots = env.get("o", [])
        if not isinstance(slots, list) or not slots:
            raise HCError("HWID key slot missing")
        for slot in slots:
            if not isinstance(slot, dict):
                continue
            try:
                nonce = bytes.fromhex(slot["a"])
                ct = bytes.fromhex(slot["b"])
                sk = _xdec(skey, nonce, aad + b"\x00w", ct)
                if len(sk) == 32:
                    return sk, aad
            except (HCError, TypeError, ValueError, KeyError):
                continue
        raise HCError("AUTH_FAILED")

    return skey, aad


class _R:
    def __init__(self, d):
        self.d, self.o = d, 0

    def take(self, n):
        if self.o + n > len(self.d):
            raise HCError("Truncated HPC1")
        v = self.d[self.o:self.o + n]
        self.o += n
        return v

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def u64(self):
        return struct.unpack(">Q", self.take(8))[0]

    def txt(self):
        s = self.u32()
        if s > 16 * 1024 * 1024:
            raise HCError("HPC1 string too long")
        return self.take(s).decode("utf-8")


def _parse_hpc1(data, label):
    r = _R(data)
    if r.take(4) != b"HPC1":
        raise HCError("Not HPC1")
    if r.u32() != 11:
        raise HCError("HPC1 field count wrong")
    name, proto, host = r.txt(), r.txt(), r.txt()
    port = r.u32()
    user, pw, payload = r.txt(), r.txt(), r.txt()
    opts_txt = r.txt()
    flags = r.u32()
    updated = r.u64()
    mode = r.txt()
    if r.o != len(data):
        raise HCError("HPC1 trailing bytes")
    try:
        opts = json.loads(opts_txt) if opts_txt else {}
    except json.JSONDecodeError:
        opts = opts_txt
    res = {"name": name, "protocol": proto, "host": host, "port": port,
           "username": user, "password": pw, "payload": payload,
           "options": opts, "flags": flags, "updated_at_ms": updated, "mode": mode}
    if label:
        res["label"] = label
    return res


def _dec_section(sec, key, aad_base):
    try:
        label = sec["a"]
        nonce = bytes.fromhex(sec["b"])
        ct = bytes.fromhex(sec["c"])
    except (KeyError, TypeError, ValueError):
        raise HCError("Bad section")
    if not isinstance(label, str) or not label:
        raise HCError("Bad section label")
    return _xdec(key, nonce, aad_base + b"\x00" + label.encode(), ct)


def _dec_sidecar(sec, key, aad_base):
    nested = sec.get("d")
    if nested is None:
        return None
    if not isinstance(nested, dict):
        raise HCError("Bad sidecar")
    label = sec.get("a", "")
    try:
        nonce = bytes.fromhex(nested["a"])
        ct = bytes.fromhex(nested["b"])
    except (KeyError, TypeError, ValueError):
        raise HCError("Bad sidecar data")
    return _xdec(key, nonce, aad_base + b"\x00" + label.encode() + b":x", ct)


def _dec_hpr1(data, key, aad_base, label):
    if not data.startswith(b"HPR1") or len(data) < 44:
        return data
    nonce, ct_tag = data[4:28], data[28:]
    tag = (label or "s0").encode()
    try:
        return _xdec(key, nonce, aad_base + b"\x00" + tag + b":r", ct_tag)
    except HCError:
        sub = _hchacha20(key, nonce[:16])
        n12 = b"\x00\x00\x00\x00" + nonce[16:]
        return _stream_xor(ct_tag[:-16], sub, n12, 1)


def _sec_list(v):
    if isinstance(v, list) and all(isinstance(x, dict) for x in v):
        return v
    if isinstance(v, dict) and all(isinstance(x, dict) for x in v.values()):
        return list(v.values())
    raise HCError("Bad section collection")


PKM = {"a": "accessMode", "c": "expiryEnabled", "d": "expiryTime", "e": "noteEnabled",
       "f": "hwidLockEnabled", "g": "hwids", "h": "loginHwidEnabled",
       "j": "loginHwidAuthorizationRequired", "l": "mobileDataOnly", "m": "blockRoot",
       "o": "providerLockEnabled", "p": "providerCodes", "v": "note"}

HC_VERSIONS = {756: "7.9.21", 759: "7.9.24", 766: "7.9.28", 789: "7.10.7", 810: "7.10.12",
               831: "7.10.19", 848: "7.10.25", 859: "7.11.1", 864: "7.11.8"}


def _ver(n):
    try:
        return f"{HC_VERSIONS[int(n)]} ({int(n)})"
    except (KeyError, TypeError, ValueError):
        return f"build-{n}"


def _norm_prot(p):
    if not isinstance(p, dict):
        return p
    return {PKM.get(k, k): v for k, v in p.items()}


class HCDecryptorV2:
    @classmethod
    def decrypt(cls, data, password=None, hwid=None):
        env = _open_outer(data)
        skey, aad_base = _derive(env, password, hwid)

        main_sec = env.get("i")
        if not isinstance(main_sec, dict):
            raise HCError("Main section missing")
        main_pt = _dec_section(main_sec, skey, aad_base)
        try:
            main_cfg = json.loads(main_pt.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HCError("Main section is not JSON")

        profiles, others = [], []
        for sec in _sec_list(env.get("j", [])):
            pt = _dec_section(sec, skey, aad_base)
            label = sec.get("a")
            if pt.startswith(b"HPR1"):
                pt = _dec_hpr1(pt, skey, aad_base, label)
            sidecar = _dec_sidecar(sec, skey, aad_base)
            if pt.startswith(b"HPC1"):
                prof = _parse_hpc1(pt, label)
                if sidecar:
                    try:
                        prof["custom_payload_sidecar"] = sidecar.decode("utf-8")
                    except UnicodeDecodeError:
                        prof["custom_payload_sidecar_hex"] = sidecar.hex()
                profiles.append(prof)
            else:
                try:
                    dec = pt.decode("utf-8")
                    if dec.startswith(("{", "[")):
                        dec = json.loads(dec)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    dec = {"hex": pt.hex()}
                others.append({"label": label, "content": dec})

        clean = []
        for p in profiles:
            cp = {"name": p.get("name", ""), "protocol": p.get("protocol", ""),
                  "host": p.get("host", ""), "port": p.get("port", 0),
                  "username": p.get("username", ""), "password": p.get("password", ""),
                  "mode": p.get("mode", "")}
            opts = p.get("options", {})
            if isinstance(opts, dict):
                for k, v in opts.items():
                    cp[k] = v
            if p.get("payload"):
                cp["payload"] = p["payload"]
            if "custom_payload_sidecar" in p:
                cp["custom_payload_sidecar"] = p["custom_payload_sidecar"]
            if "custom_payload_sidecar_hex" in p:
                cp["custom_payload_sidecar_hex"] = p["custom_payload_sidecar_hex"]
            clean.append(cp)

        result = {
            "app_version": _ver(env.get("n")),
            "config": clean,
            "protections": _norm_prot(main_cfg.get("g", {}) if isinstance(main_cfg, dict) else {})
        }
        if others:
            result["other_sections"] = others
        return result

    @classmethod
    def execute(cls, file_bytes):
        try:
            data = file_bytes
            if isinstance(data, str):
                data = data.encode('utf-8', errors='ignore')
            result = cls.decrypt(data)
            return json.dumps(result, indent=4, ensure_ascii=False, default=str)
        except Exception:
            return None
