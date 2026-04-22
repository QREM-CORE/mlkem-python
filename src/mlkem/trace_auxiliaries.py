# --- Hardware-Instrumented Auxiliaries ---
# Wraps the pure NIST FIPS 203 algorithms from auxiliaries.py with:
#   - Trace logging for hardware validation (encode, decode, compress, decompress,
#     CBD, NTT, INTT, MultiplyNTTs)
#   - Radix-4 NTT / INTT variants matched to the RTL implementation
#
# All unchanged functions (H, J, G, PRF_eta, XOF, BitsToBytes, BytesToBits,
# SampleNTT, BaseCaseMultiply) are re-exported from auxiliaries.py so callers
# only need to import this module.

from .auxiliaries import *

# === Precomputed Values for NTT ===
_BitRev7 = lambda i: [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319,
    1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617,
    1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583, 2649,
    1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156,
    3015, 3050, 1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298,
    2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757,
    2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775,
    886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154][i % 128]

_2BitRev7_1 = lambda i: [
    17, -17, 2761, -2761, 583, -583, 2649, -2649,
    1637, -1637, 723, -723, 2288, -2288, 1100, -1100,
    1409, -1409, 2662, -2662, 3281, -3281, 233, -233,
    756, -756, 2156, -2156, 3015, -3015, 3050, -3050,
    1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789,
    1847, -1847, 952, -952, 1461, -1461, 2687, -2687,
    939, -939, 2308, -2308, 2437, -2437, 2388, -2388,
    733, -733, 2337, -2337, 268, -268, 641, -641,
    1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220,
    375, -375, 2549, -2549, 2090, -2090, 1645, -1645,
    1063, -1063, 319, -319, 2773, -2773, 757, -757,
    2099, -2099, 561, -561, 2466, -2466, 2594, -2594,
    2804, -2804, 1092, -1092, 403, -403, 1026, -1026,
    1143, -1143, 2150, -2150, 2775, -2775, 886, -886,
    1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029,
    2110, -2110, 2935, -2935, 885, -885, 2154, -2154
][i % 128]

# =============================================================================
# === Trace Logs
# === Module-level lists — call clear_all_traces() between test cases.
# =============================================================================

mod_mul_traces      = []   # every (a * b) % q                   → mod_mul.sv
mod_add_traces      = []   # every (a + b) % q                   → mod_add.sv
mod_sub_traces      = []   # every (a - b) % q                   → mod_sub.sv
butterfly_traces    = []   # every full butterfly (PE) operation  → pe0.sv / pe3.sv
ntt_stage_traces    = []   # 256 coefficients snapshotted after each NTT stage
cbd_traces          = []   # every SamplePolyCBD_eta call
intt_stage_traces   = []   # 256 coefficients snapshotted after each INTT stage
multiply_ntt_traces = []   # every MultiplyNTTs call             → pointwise_mul.sv
compress_traces     = []   # every Compress_d call               → compress.sv
decompress_traces   = []   # every Decompress_d call             → decompress.sv
byte_encode_traces  = []   # every ByteEncode_d call             → byte_encode.sv
byte_decode_traces  = []   # every ByteDecode_d call             → byte_decode.sv
bits_to_bytes_traces = []  # every BitsToBytes call              → bits_to_bytes.sv
bytes_to_bits_traces = []  # every BytesToBits call              → bytes_to_bits.sv

def clear_all_traces():
    """Reset all trace buffers — call this before each test case."""
    mod_mul_traces.clear()
    mod_add_traces.clear()
    mod_sub_traces.clear()
    butterfly_traces.clear()
    ntt_stage_traces.clear()
    cbd_traces.clear()
    intt_stage_traces.clear()
    multiply_ntt_traces.clear()
    compress_traces.clear()
    decompress_traces.clear()
    byte_encode_traces.clear()
    byte_decode_traces.clear()
    bits_to_bytes_traces.clear()
    bytes_to_bits_traces.clear()

# =============================================================================
# === Instrumented Arithmetic Primitives
# =============================================================================

def _log_mul(a, b):
    """(a * b) % q — maps to mod_mul.sv"""
    result = (a * b) % q
    mod_mul_traces.append({"a": a, "b": b, "result": result})
    return result

def _log_add(a, b):
    """(a + b) % q — maps to mod_add.sv"""
    result = (a + b) % q
    mod_add_traces.append({"a": a, "b": b, "result": result})
    return result

def _log_sub(a, b):
    """(a - b) % q — maps to mod_sub.sv"""
    result = (a - b) % q
    mod_sub_traces.append({"a": a, "b": b, "result": result})
    return result

# =============================================================================
# === Instrumented Algorithm Overrides
# =============================================================================

def Compress_d(x: list[int], d: int) -> list[int]:
    def compress_coefficient(x2, d):
        return int(((1 << d) * x2 + q // 2) // q) % (1 << d)
    assert 1 <= d < 12
    result = [compress_coefficient(i, d) for i in x]
    compress_traces.append({
        "call_index": len(compress_traces),
        "d":          d,
        "input":      list(x),
        "output":     list(result),
    })
    return result


def Decompress_d(y: list[int], d: int) -> list[int]:
    def decompress_coefficient(y2, d):
        return int((q * y2 + (1 << d) // 2) // (1 << d)) % q
    assert 1 <= d < 12
    result = [decompress_coefficient(i, d) for i in y]
    decompress_traces.append({
        "call_index": len(decompress_traces),
        "d":          d,
        "input":      list(y),
        "output":     list(result),
    })
    return result


# FIPS203 Algorithm 5 — ByteEncode_d

def ByteEncode_d(F: list[int], d: int) -> bytes:
    assert len(F) == 256
    assert 1 <= d <= 12

    bits = []
    if d < 12:
        m = 1 << d
        for a in F:
            assert 0 <= a < m
            for j in range(d):
                bits.append(a & 1)
                a = (a - (a & 1)) >> 1
    else:  # d == 12
        for a in F:
            assert 0 <= a < q
            for j in range(12):
                bits.append(a & 1)
                a = (a - (a & 1)) >> 1

    result = BitsToBytes(bits)
    byte_encode_traces.append({
        "call_index": len(byte_encode_traces),
        "d":          d,
        "input":      list(F),
        "output":     result.hex(),
    })
    return result


# FIPS203 Algorithm 6 — ByteDecode_d

def ByteDecode_d(B: bytes, d: int) -> list[int]:
    assert 1 <= d <= 12
    assert len(B) * 8 == 256 * d

    bits = BytesToBits(B)
    m = (1 << d) if d < 12 else q
    F = []
    for i in range(256):
        a = 0
        base = i * d
        for j in range(d):
            a += (bits[base + j] & 1) << j
        F.append(a % m)

    byte_decode_traces.append({
        "call_index": len(byte_decode_traces),
        "d":          d,
        "input":      B.hex(),
        "output":     list(F),
    })
    return F


# FIPS203 Algorithm 3 — BitsToBytes

def BitsToBytes(bits: list[int]) -> bytes:
    assert len(bits) % 8 == 0
    out = bytearray(len(bits) // 8)
    for i, bit in enumerate(bits):
        out[i >> 3] |= (bit & 1) << (i & 7)
    result = bytes(out)
    bits_to_bytes_traces.append({
        "call_index": len(bits_to_bytes_traces),
        "input":      list(bits),
        "output":     result.hex(),
    })
    return result


# FIPS203 Algorithm 4 — BytesToBits

def BytesToBits(B: bytes) -> list[int]:
    b = []
    for byte in B:
        for j in range(8):
            b.append(byte & 1)
            byte >>= 1
    bytes_to_bits_traces.append({
        "call_index": len(bytes_to_bits_traces),
        "input":      B.hex(),
        "output":     list(b),
    })
    return b


def SamplePolyCBD_eta(B: bytes, eta: int) -> list[int]:
    assert eta in (2, 3)
    assert len(B) == 64 * eta
    f = [0] * 256
    t = BytesToBits(B)
    for i in range(256):
        x = sum(t[2 * eta * i + j] for j in range(eta))
        y = sum(t[2 * eta * i + eta + j] for j in range(eta))
        f[i] = (x - y) % q
    cbd_traces.append({"call_index": len(cbd_traces), "coeffs": list(f)})
    return f


def NTT(f: list[int]) -> list[int]:
    """Radix-4 NTT matched to RTL implementation (3 R4 passes + 1 R2 pass)."""
    assert len(f) == 256
    a = list(f)

    OMEGA1_4 = 1729  # ζ^64 mod q — primitive 4th root of unity

    # Build R4NTT_ROM: 21 triplets (ω1, ω2, ω3), ω3 = ω1*ω2 mod q
    R4NTT_ROM = []
    w2 = _BitRev7(1);  w1 = _BitRev7(2)
    R4NTT_ROM.append((w1, w2, (w1 * w2) % q))
    for k in range(4):
        w2 = _BitRev7(4 + k);  w1 = _BitRev7(8 + 2 * k)
        R4NTT_ROM.append((w1, w2, (w1 * w2) % q))
    for k in range(16):
        w2 = _BitRev7(16 + k);  w1 = _BitRev7(32 + 2 * k)
        R4NTT_ROM.append((w1, w2, (w1 * w2) % q))

    # OMEGA_ROM: 64 entries for the final Radix-2 pass
    OMEGA_ROM = [_BitRev7(64 + b) for b in range(64)]

    ntt_stage_traces.append({"stage": "input", "length": None, "coeffs": list(a)})

    rom_idx = 0
    for p in range(3, 0, -1):
        stride   = 4 ** p   # 64 → 16 → 4
        pass_num = 4 - p    #  1 →  2 → 3

        for k in range(256 // (4 * stride)):
            omega1, omega2, omega3 = R4NTT_ROM[rom_idx];  rom_idx += 1
            for j in range(stride):
                m  = 4 * k * stride + j
                r0 = (a[m]          + a[m + 2*stride] * omega2) % q
                r1 = (a[m]          - a[m + 2*stride] * omega2) % q
                r2 = (a[m + stride] * omega1 + a[m + 3*stride] * omega3) % q
                r3 = (a[m + stride] * omega1 - a[m + 3*stride] * omega3) % q
                a[m]            = (r0 + r2)            % q
                a[m + stride]   = (r0 - r2)            % q
                a[m + 2*stride] = (r1 + r3 * OMEGA1_4) % q
                a[m + 3*stride] = (r1 - r3 * OMEGA1_4) % q

        ntt_stage_traces.append({
            "stage":  f"r4_pass_{pass_num}",
            "pass":   pass_num,
            "length": stride,
            "coeffs": list(a),
        })

    # Final Radix-2 pass
    for j in range(0, 256, 4):
        omega = OMEGA_ROM[j // 4]
        u0 = a[j];    u1 = a[j + 1]
        v0 = a[j + 2] * omega % q
        v1 = a[j + 3] * omega % q
        a[j]     = (u0 + v0) % q
        a[j + 2] = (u0 - v0) % q
        a[j + 1] = (u1 + v1) % q
        a[j + 3] = (u1 - v1) % q

    ntt_stage_traces.append({"stage": "r2_final", "pass": 4, "length": 2, "coeffs": list(a)})
    return a


def NTT_inv(f_hat: list[int]) -> list[int]:
    """Radix-4 INTT matched to RTL implementation (1 R2 pass + 3 R4 passes)."""
    assert len(f_hat) == 256
    a = list(f_hat)

    INV2     = 1665   # 2^-1 mod 3329
    INV4     = 2497   # 4^-1 mod 3329
    OMEGA1_4 = 1729   # ζ^64 mod q

    OMEGA_INV_ROM = [(-_BitRev7(127 - b) * INV2) % q for b in range(64)]

    R4INTT_ROM = []
    for k in range(16):
        za = _BitRev7(62 - 2*k);  zb = _BitRev7(31 - k)
        R4INTT_ROM.append(((-za * INV4) % q, (-zb * INV2) % q, (za * zb * INV4) % q))
    for k in range(4):
        za = _BitRev7(14 - 2*k);  zb = _BitRev7(7 - k)
        R4INTT_ROM.append(((-za * INV4) % q, (-zb * INV2) % q, (za * zb * INV4) % q))
    za = _BitRev7(2);  zb = _BitRev7(1)
    R4INTT_ROM.append(((-za * INV4) % q, (-zb * INV2) % q, (za * zb * INV4) % q))

    intt_stage_traces.append({"stage": "input", "length": None, "coeffs": list(a)})

    # First Radix-2 pass
    for j in range(0, 256, 4):
        w  = OMEGA_INV_ROM[j >> 2]
        t0 = a[j];  t1 = a[j + 1]
        a[j]     = (a[j + 2] + t0) * INV2 % q
        a[j + 2] = (t0 - a[j + 2]) * w    % q
        a[j + 1] = (a[j + 3] + t1) * INV2 % q
        a[j + 3] = (t1 - a[j + 3]) * w    % q

    intt_stage_traces.append({"stage": "r2_first", "pass": 1, "length": 2, "coeffs": list(a)})

    rom_idx = 0
    for p in range(1, 4):
        stride   = 4 ** p   # 4 → 16 → 64
        pass_num = p + 1    # 2 →  3 →  4

        for k in range(256 // (4 * stride)):
            w1, w2, w3 = R4INTT_ROM[rom_idx];  rom_idx += 1
            for j in range(stride):
                m  = 4 * k * stride + j
                t0 = (a[m]            + a[m +   stride]) * INV2     % q
                t1 = (a[m]            - a[m +   stride]) * OMEGA1_4 % q
                t2 = (a[m + 2*stride] + a[m + 3*stride]) * INV2     % q
                t3 = (a[m + 2*stride] - a[m + 3*stride])             % q
                a[m]            = (t0 + t2) * INV2 % q
                a[m +   stride] = (t1 + t3) * w1   % q
                a[m + 2*stride] = (t0 - t2) * w2   % q
                a[m + 3*stride] = (t1 - t3) * w3   % q

        intt_stage_traces.append({
            "stage":  f"r4_pass_{pass_num}",
            "pass":   pass_num,
            "length": stride,
            "coeffs": list(a),
        })

    return a


def MultiplyNTTs(f_hat: list[int], g_hat: list[int]) -> list[int]:
    assert len(f_hat) == 256 and len(g_hat) == 256
    h_hat = [0] * 256
    for i in range(128):
        h_hat[2*i], h_hat[2*i + 1] = BaseCaseMultiply(
            f_hat[2*i], f_hat[2*i + 1],
            g_hat[2*i], g_hat[2*i + 1],
            _2BitRev7_1(i)
        )
    multiply_ntt_traces.append({
        "call_index": len(multiply_ntt_traces),
        "f_hat":      list(f_hat),
        "g_hat":      list(g_hat),
        "h_hat":      list(h_hat),
    })
    return h_hat
