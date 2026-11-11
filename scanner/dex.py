"""
Minimal, fast Dalvik Executable (DEX) parser + bytecode call-site scanner.

Why a custom parser?
  The previous engine grepped raw DEX bytes for substrings like b"su" or b"DES",
  which matched almost every app (false positives) and only looked at the
  smallest classes*.dex (false negatives). Parsing the DEX tables gives us:

    * the exact string pool (secrets / URLs without binary noise)
    * every referenced method (does the app *call* WebSettings.setJavaScriptEnabled?)
    * class hierarchy (who implements X509TrustManager / HostnameVerifier?)
    * method bytecode, scanned linearly with light constant tracking, so we can
      tell `setJavaScriptEnabled(true)` from `(false)`, or read the transformation
      string passed to `Cipher.getInstance("AES/ECB/PKCS5Padding")`.

Only the pieces of the format we need are implemented. Everything is defensive:
a malformed DEX never crashes the scan, it just yields less data.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# Instruction widths (in 16-bit code units) indexed by opcode.
# Source: https://source.android.com/docs/core/runtime/dalvik-bytecode
# --------------------------------------------------------------------------- #
_W = [1] * 256


def _set(lo: int, hi: int, w: int) -> None:
    for i in range(lo, hi + 1):
        _W[i] = w


_set(0x00, 0x01, 1)
_set(0x02, 0x02, 2)
_set(0x03, 0x03, 3)
_set(0x04, 0x04, 1)
_set(0x05, 0x05, 2)
_set(0x06, 0x06, 3)
_set(0x07, 0x07, 1)
_set(0x08, 0x08, 2)
_set(0x09, 0x09, 3)
_set(0x0A, 0x12, 1)
_set(0x13, 0x13, 2)
_set(0x14, 0x14, 3)
_set(0x15, 0x16, 2)
_set(0x17, 0x17, 3)
_set(0x18, 0x18, 5)
_set(0x19, 0x1A, 2)
_set(0x1B, 0x1B, 3)
_set(0x1C, 0x1C, 2)
_set(0x1D, 0x1E, 1)
_set(0x1F, 0x20, 2)
_set(0x21, 0x21, 1)
_set(0x22, 0x23, 2)
_set(0x24, 0x26, 3)
_set(0x27, 0x28, 1)
_set(0x29, 0x29, 2)
_set(0x2A, 0x2C, 3)
_set(0x2D, 0x3D, 2)
_set(0x3E, 0x43, 1)
_set(0x44, 0x6D, 2)
_set(0x6E, 0x72, 3)
_set(0x73, 0x73, 1)
_set(0x74, 0x78, 3)
_set(0x79, 0x7A, 1)
_set(0x7B, 0x8F, 1)
_set(0x90, 0xAF, 2)
_set(0xB0, 0xCF, 1)
_set(0xD0, 0xE2, 2)
_set(0xE3, 0xF9, 1)
_set(0xFA, 0xFB, 4)
_set(0xFC, 0xFD, 3)
_set(0xFE, 0xFF, 2)
WIDTH = tuple(_W)

# Opcodes that write a 4-bit destination register vA (formats 12x/22c/22s/...).
_WRITE_A4 = set([0x01, 0x04, 0x21, 0x20, 0x23]) | set(range(0x52, 0x59)) \
    | set(range(0x7B, 0x90)) | set(range(0xB0, 0xD0)) | set(range(0xD0, 0xD8))
# Opcodes that write an 8-bit destination register vAA.
_WRITE_AA = set([0x02, 0x05, 0x08, 0x0A, 0x0B, 0x0D, 0x1C, 0x22]) \
    | set(range(0x16, 0x1A)) | set(range(0x2D, 0x32)) | set(range(0x44, 0x4B)) \
    | set(range(0x60, 0x67)) | set(range(0x90, 0xB0)) | set(range(0xD8, 0xE3)) \
    | {0xFE, 0xFF}
_WIDE_DEST = {0x04, 0x05, 0x06, 0x0B, 0x16, 0x17, 0x18, 0x19, 0x45, 0x53, 0x61}

INVOKE_OPS = set(range(0x6E, 0x73)) | set(range(0x74, 0x79))
_INVOKE_RE_BYTES = bytes(sorted(INVOKE_OPS))

ACC_INTERFACE = 0x200
ACC_ABSTRACT = 0x400
ACC_NATIVE = 0x100


def _uleb(data: bytes, off: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            return result, off
        shift += 7
        if shift > 35:
            raise ValueError("bad uleb128")


def _mutf8(raw: bytes) -> str:
    raw = raw.replace(b"\xc0\x80", b"\x00")
    try:
        return raw.decode("utf-8", "surrogatepass")
    except UnicodeDecodeError:
        return raw.decode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class MethodRef:
    cls: str          # Lcom/foo/Bar;
    name: str
    params: Tuple[str, ...]
    ret: str

    @property
    def sig(self) -> str:
        return f"{self.cls}->{self.name}({''.join(self.params)}){self.ret}"


@dataclass
class EncodedMethod:
    method_idx: int
    access: int
    code_off: int


@dataclass
class ClassDef:
    name: str
    access: int
    superclass: Optional[str]
    interfaces: Tuple[str, ...]
    methods: List[EncodedMethod] = field(default_factory=list)


@dataclass
class CallSite:
    """A resolved invoke of a watched API."""
    api: str                    # key of the watched API
    caller_class: str           # Lcom/foo/Bar;
    caller_method: str          # onCreate
    args: List[object]          # tracked values: int, ("str", s), ("bytes", s) or None
    dex: str

    @property
    def location(self) -> str:
        return f"{descriptor_to_java(self.caller_class)}.{self.caller_method}()"


def descriptor_to_java(desc: str) -> str:
    if desc.startswith("L") and desc.endswith(";"):
        return desc[1:-1].replace("/", ".")
    return desc


# --------------------------------------------------------------------------- #
# Watched API specification
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ApiSpec:
    """
    key      : identifier used by the rules
    cls      : declaring class descriptor or "*" (match any class - useful for
               Context methods that are invoked through Activity/Service types)
    name     : method name
    params   : exact parameter descriptor string (e.g. "Ljava/lang/String;I"),
               or None to accept any overload
    static   : whether it's a static method (affects arg register layout)
    """
    key: str
    cls: str
    name: str
    params: Optional[str] = None
    static: bool = False


class DexFile:
    def __init__(self, data: bytes, name: str = "classes.dex"):
        if len(data) < 0x70 or not data.startswith(b"dex\n"):
            raise ValueError(f"{name}: not a DEX file")
        self.data = data
        self.name = name
        (self.string_ids_size, self.string_ids_off,
         self.type_ids_size, self.type_ids_off,
         self.proto_ids_size, self.proto_ids_off,
         self.field_ids_size, self.field_ids_off,
         self.method_ids_size, self.method_ids_off,
         self.class_defs_size, self.class_defs_off) = struct.unpack_from("<12I", data, 0x38)
        self._strings: Optional[List[str]] = None
        self._types: Optional[List[str]] = None
        self._protos: Optional[List[Tuple[Tuple[str, ...], str]]] = None
        self._methods: Optional[List[MethodRef]] = None
        self._fields: Optional[List[Tuple[str, str, str]]] = None
        self._classes: Optional[List[ClassDef]] = None

    # ---- tables ---------------------------------------------------------- #
    @property
    def strings(self) -> List[str]:
        if self._strings is None:
            d = self.data
            offs = struct.unpack_from(f"<{self.string_ids_size}I", d, self.string_ids_off)
            out = []
            find = d.find
            for o in offs:
                try:
                    _, p = _uleb(d, o)
                    end = find(b"\x00", p)
                    out.append(_mutf8(d[p:end]))
                except Exception:
                    out.append("")
            self._strings = out
        return self._strings

    @property
    def types(self) -> List[str]:
        if self._types is None:
            s = self.strings
            idx = struct.unpack_from(f"<{self.type_ids_size}I", self.data, self.type_ids_off)
            self._types = [s[i] if i < len(s) else "" for i in idx]
        return self._types

    @property
    def protos(self) -> List[Tuple[Tuple[str, ...], str]]:
        if self._protos is None:
            d = self.data
            t = self.types
            out = []
            for i in range(self.proto_ids_size):
                _shorty, ret, poff = struct.unpack_from("<3I", d, self.proto_ids_off + i * 12)
                params: Tuple[str, ...] = ()
                if poff:
                    n = struct.unpack_from("<I", d, poff)[0]
                    params = tuple(t[x] for x in struct.unpack_from(f"<{n}H", d, poff + 4))
                out.append((params, t[ret]))
            self._protos = out
        return self._protos

    @property
    def methods(self) -> List[MethodRef]:
        if self._methods is None:
            d = self.data
            t, s, p = self.types, self.strings, self.protos
            out = []
            raw = struct.unpack_from(f"<{self.method_ids_size * 4}H", d, self.method_ids_off) \
                if self.method_ids_size else ()
            for i in range(self.method_ids_size):
                cls_idx, proto_idx, n_lo, n_hi = raw[i * 4: i * 4 + 4]
                params, ret = p[proto_idx]
                out.append(MethodRef(t[cls_idx], s[n_lo | (n_hi << 16)], params, ret))
            self._methods = out
        return self._methods

    @property
    def fields(self) -> List[Tuple[str, str, str]]:
        if self._fields is None:
            d = self.data
            t, s = self.types, self.strings
            out = []
            for i in range(self.field_ids_size):
                c, ty, n = struct.unpack_from("<HHI", d, self.field_ids_off + i * 8)
                out.append((t[c], t[ty], s[n]))
            self._fields = out
        return self._fields

    @property
    def classes(self) -> List[ClassDef]:
        if self._classes is None:
            d = self.data
            t = self.types
            out = []
            for i in range(self.class_defs_size):
                (cidx, acc, sup, ifoff, _src, _ann, cdoff, _sv) = struct.unpack_from(
                    "<8I", d, self.class_defs_off + i * 32)
                ifaces: Tuple[str, ...] = ()
                if ifoff:
                    n = struct.unpack_from("<I", d, ifoff)[0]
                    ifaces = tuple(t[x] for x in struct.unpack_from(f"<{n}H", d, ifoff + 4))
                cd = ClassDef(t[cidx], acc, t[sup] if sup != 0xFFFFFFFF else None, ifaces)
                if cdoff:
                    try:
                        cd.methods = self._class_methods(cdoff)
                    except Exception:
                        pass
                out.append(cd)
            self._classes = out
        return self._classes

    def _class_methods(self, off: int) -> List[EncodedMethod]:
        d = self.data
        sf, off = _uleb(d, off)
        inf, off = _uleb(d, off)
        dm, off = _uleb(d, off)
        vm, off = _uleb(d, off)
        for _ in range(sf + inf):
            _, off = _uleb(d, off)
            _, off = _uleb(d, off)
        out = []
        for count in (dm, vm):
            idx = 0
            for _ in range(count):
                diff, off = _uleb(d, off)
                acc, off = _uleb(d, off)
                code, off = _uleb(d, off)
                idx += diff
                out.append(EncodedMethod(idx, acc, code))
        return out

    # ---- code ------------------------------------------------------------ #
    def code_units(self, code_off: int) -> Optional[Sequence[int]]:
        if not code_off:
            return None
        d = self.data
        insns_size = struct.unpack_from("<I", d, code_off + 12)[0]
        start = code_off + 16
        if insns_size == 0 or start + insns_size * 2 > len(d):
            return None
        return memoryview(d)[start:start + insns_size * 2].cast("H")

    def code_bytes(self, code_off: int) -> bytes:
        d = self.data
        insns_size = struct.unpack_from("<I", d, code_off + 12)[0]
        start = code_off + 16
        return d[start:start + insns_size * 2]


# --------------------------------------------------------------------------- #
# Bytecode walking
# --------------------------------------------------------------------------- #
def iter_instructions(u: Sequence[int]):
    """Yield (pc, opcode) for every instruction, skipping data payloads."""
    pc = 0
    n = len(u)
    while pc < n:
        u0 = u[pc]
        op = u0 & 0xFF
        if op == 0 and u0 != 0:
            if u0 == 0x0100 and pc + 1 < n:          # packed-switch-payload
                pc += u[pc + 1] * 2 + 4
                continue
            if u0 == 0x0200 and pc + 1 < n:          # sparse-switch-payload
                pc += u[pc + 1] * 4 + 2
                continue
            if u0 == 0x0300 and pc + 3 < n:          # fill-array-data-payload
                w = u[pc + 1]
                sz = u[pc + 2] | (u[pc + 3] << 16)
                pc += (sz * w + 1) // 2 + 4
                continue
        yield pc, op
        pc += WIDTH[op]


def _s16(v: int) -> int:
    return v - 0x10000 if v & 0x8000 else v


def _s32(v: int) -> int:
    return v - 0x100000000 if v & 0x80000000 else v


def scan_method_calls(u: Sequence[int],
                      watched: Dict[int, Tuple[str, bool, Tuple[str, ...]]],
                      strings: List[str],
                      helpers: Dict[int, str]) -> List[Tuple[str, List[object]]]:
    """
    Linear scan of a method body with light constant/move tracking.

    watched : method_idx -> (api_key, is_static, params)
    helpers : method_idx -> helper kind ("getBytes" / "b64decode") used to
              propagate constant strings into byte arrays.

    Returns list of (api_key, [arg values]) where arg values are
    int / ("str", s) / ("bytes", s) / None (unknown).
    """
    regs: Dict[int, object] = {}
    pending_result: object = None
    out: List[Tuple[str, List[object]]] = []
    n = len(u)
    pc = 0
    while pc < n:
        u0 = u[pc]
        op = u0 & 0xFF
        if op == 0 and u0 != 0:
            if u0 == 0x0100 and pc + 1 < n:
                pc += u[pc + 1] * 2 + 4
                continue
            if u0 == 0x0200 and pc + 1 < n:
                pc += u[pc + 1] * 4 + 2
                continue
            if u0 == 0x0300 and pc + 3 < n:
                w = u[pc + 1]
                sz = u[pc + 2] | (u[pc + 3] << 16)
                pc += (sz * w + 1) // 2 + 4
                continue
        w = WIDTH[op]
        if pc + w > n:
            break
        if op in INVOKE_OPS:
            midx = u[pc + 1]
            if op <= 0x72:
                cnt = u0 >> 12
                g = (u0 >> 8) & 0xF
                c = u[pc + 2]
                argregs = [c & 0xF, (c >> 4) & 0xF, (c >> 8) & 0xF, (c >> 12) & 0xF, g][:cnt]
            else:
                cnt = u0 >> 8
                first = u[pc + 2]
                argregs = list(range(first, first + cnt))
            pending_result = None
            if midx in watched:
                key, is_static, params = watched[midx]
                vals = []
                pos = 0 if is_static else 1
                for p in params:
                    vals.append(regs.get(argregs[pos]) if pos < len(argregs) else None)
                    pos += 2 if p in ("J", "D") else 1
                out.append((key, vals))
            h = helpers.get(midx)
            if h and argregs:
                src = regs.get(argregs[0])
                if h == "getBytes" and isinstance(src, tuple) and src[0] == "str":
                    pending_result = ("bytes", src[1])
                elif h == "b64decode" and isinstance(src, tuple) and src[0] == "str":
                    pending_result = ("bytes", "base64:" + src[1])
                elif h == "toCharArray" and isinstance(src, tuple) and src[0] == "str":
                    pending_result = ("bytes", src[1])
        elif op == 0x12:                                   # const/4
            b = u0 >> 12
            regs[(u0 >> 8) & 0xF] = b - 16 if b & 8 else b
        elif op == 0x13:                                   # const/16
            regs[u0 >> 8] = _s16(u[pc + 1])
        elif op == 0x14:                                   # const
            regs[u0 >> 8] = _s32(u[pc + 1] | (u[pc + 2] << 16))
        elif op == 0x15:                                   # const/high16
            regs[u0 >> 8] = _s32(u[pc + 1] << 16)
        elif op == 0x1A:                                   # const-string
            si = u[pc + 1]
            regs[u0 >> 8] = ("str", strings[si] if si < len(strings) else "")
        elif op == 0x1B:                                   # const-string/jumbo
            si = u[pc + 1] | (u[pc + 2] << 16)
            regs[u0 >> 8] = ("str", strings[si] if si < len(strings) else "")
        elif op == 0x07 or op == 0x01:                     # move-object / move
            regs[(u0 >> 8) & 0xF] = regs.get(u0 >> 12)
        elif op == 0x08 or op == 0x02:                     # move-object/from16
            regs[u0 >> 8] = regs.get(u[pc + 1])
        elif op == 0x09 or op == 0x03:                     # move/16
            regs[u[pc + 1]] = regs.get(u[pc + 2])
        elif op == 0x0C:                                   # move-result-object
            regs[u0 >> 8] = pending_result
            pending_result = None
        elif op in _WRITE_A4:
            a = (u0 >> 8) & 0xF
            regs.pop(a, None)
            if op in _WIDE_DEST:
                regs.pop(a + 1, None)
        elif op in _WRITE_AA:
            a = u0 >> 8
            regs.pop(a, None)
            if op in _WIDE_DEST:
                regs.pop(a + 1, None)
        pc += w
    return out


def method_is_trivial(u: Sequence[int], methods: List[MethodRef]) -> Tuple[bool, Optional[int]]:
    """
    Detect "do nothing" bodies (used for trust-all TrustManagers and
    always-true HostnameVerifiers).

    Returns (trivial, returned_const):
      trivial         True when the body never throws and only calls Kotlin
                      null-check intrinsics.
      returned_const  The constant returned (for boolean methods), else None.
    """
    regs: Dict[int, int] = {}
    returned: Optional[int] = None
    for pc, op in iter_instructions(u):
        u0 = u[pc]
        if op == 0x00 or op == 0x0E:                 # nop / return-void
            continue
        if op == 0x12:
            b = u0 >> 12
            regs[(u0 >> 8) & 0xF] = b - 16 if b & 8 else b
            continue
        if op == 0x13:
            regs[u0 >> 8] = _s16(u[pc + 1])
            continue
        if op == 0x0F:                               # return vAA
            returned = regs.get(u0 >> 8)
            continue
        if op in (0x1A, 0x1B, 0x07, 0x08, 0x01, 0x02):  # const-string / moves
            continue
        if op in INVOKE_OPS:
            m = methods[u[pc + 1]] if u[pc + 1] < len(methods) else None
            if m and m.cls.startswith("Lkotlin/jvm/internal/Intrinsics;"):
                continue
            return False, None
        return False, None                           # throw, branches, field access...
    return True, returned


# --------------------------------------------------------------------------- #
# Aggregated index over every classes*.dex in the APK
# --------------------------------------------------------------------------- #
HELPER_SPECS = [
    ("getBytes", "Ljava/lang/String;", "getBytes"),
    ("toCharArray", "Ljava/lang/String;", "toCharArray"),
    ("b64decode", "Landroid/util/Base64;", "decode"),
]


class DexIndex:
    """Holds every DEX of an APK and answers the questions rules need."""

    def __init__(self, dex_blobs: Iterable[Tuple[str, bytes]], log: Callable[[str], None] = print):
        self.dexes: List[DexFile] = []
        self.errors: List[str] = []
        for name, blob in dex_blobs:
            try:
                self.dexes.append(DexFile(blob, name))
            except Exception as e:  # pragma: no cover - defensive
                self.errors.append(f"{name}: {e}")
        self.log = log
        self._class_names: Optional[set] = None
        self._method_sigs: Optional[set] = None

    # ---- cheap inventory ------------------------------------------------- #
    def iter_strings(self) -> Iterable[Tuple[str, str]]:
        for dx in self.dexes:
            for s in dx.strings:
                yield dx.name, s

    @property
    def class_names(self) -> set:
        if self._class_names is None:
            self._class_names = {c.name for dx in self.dexes for c in dx.classes}
        return self._class_names

    @property
    def referenced_types(self) -> set:
        return {t for dx in self.dexes for t in dx.types}

    def has_class(self, java_name: str) -> bool:
        return ("L" + java_name.replace(".", "/") + ";") in self.class_names

    def references_method(self, cls: str, name: str) -> bool:
        for dx in self.dexes:
            for m in dx.methods:
                if m.name == name and (cls == "*" or m.cls == cls):
                    return True
        return False

    def references_field(self, cls: str, name: str) -> bool:
        for dx in self.dexes:
            for c, _t, n in dx.fields:
                if n == name and c == cls:
                    return True
        return False

    def implementors(self, iface_or_super: Sequence[str]) -> List[Tuple[DexFile, ClassDef]]:
        wanted = set(iface_or_super)
        out = []
        for dx in self.dexes:
            for c in dx.classes:
                if c.access & ACC_INTERFACE:
                    continue
                if c.superclass in wanted or wanted.intersection(c.interfaces):
                    out.append((dx, c))
        return out

    # ---- bytecode call-site scan ---------------------------------------- #
    def find_calls(self, specs: Sequence[ApiSpec],
                   include_class: Callable[[str], bool] = lambda c: True,
                   max_per_api: int = 40) -> Dict[str, List[CallSite]]:
        results: Dict[str, List[CallSite]] = {s.key: [] for s in specs}
        for dx in self.dexes:
            watched: Dict[int, Tuple[str, bool, Tuple[str, ...]]] = {}
            helpers: Dict[int, str] = {}
            for i, m in enumerate(dx.methods):
                for s in specs:
                    if m.name != s.name:
                        continue
                    if s.cls != "*" and m.cls != s.cls:
                        continue
                    if s.params is not None and "".join(m.params) != s.params:
                        continue
                    watched[i] = (s.key, s.static, m.params)
                    break
                for kind, hc, hn in HELPER_SPECS:
                    if m.cls == hc and m.name == hn:
                        helpers[i] = kind
            if not watched:
                continue
            # Byte-level pre-filter: an invoke opcode followed by any byte and
            # the 16-bit method index. False hits are possible (unaligned),
            # misses are not, so we only fully decode candidate methods.
            idx_alts = b"|".join(re.escape(struct.pack("<H", i)) for i in watched if i <= 0xFFFF)
            if not idx_alts:
                continue
            pre = re.compile(b"[" + re.escape(_INVOKE_RE_BYTES) + b"].(?:" + idx_alts + b")", re.S)
            strings = dx.strings
            methods = dx.methods
            for c in dx.classes:
                if not include_class(c.name):
                    continue
                for em in c.methods:
                    if not em.code_off:
                        continue
                    try:
                        raw = dx.code_bytes(em.code_off)
                        if not pre.search(raw):
                            continue
                        u = dx.code_units(em.code_off)
                        if u is None:
                            continue
                        hits = scan_method_calls(u, watched, strings, helpers)
                    except Exception:
                        continue
                    if not hits:
                        continue
                    mname = methods[em.method_idx].name if em.method_idx < len(methods) else "?"
                    for key, args in hits:
                        lst = results[key]
                        if len(lst) < max_per_api:
                            lst.append(CallSite(key, c.name, mname, args, dx.name))
        return results

    def method_body(self, dx: DexFile, em: EncodedMethod) -> Optional[Sequence[int]]:
        try:
            return dx.code_units(em.code_off)
        except Exception:
            return None
