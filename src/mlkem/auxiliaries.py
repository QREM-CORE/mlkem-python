# From https://github.com/ncbor/fips203-py/blob/main/auxiliaries.py
# --- FIPS203 Section 4: Auiliary Algorithms ---

from Crypto.Hash import SHA3_256, SHA3_512, SHAKE128, SHAKE256

q = 3329
n = 256
eta = 2 # based on the requirement for Kyber768
# =============================================================================
# === Trace Logs
# === These are module-level lists so any file that imports auxiliaries
# === can clear and read them (same pattern as ntt_traces in Internal_kpke)
# =============================================================================

mod_mul_traces   = []   # every (a * b) % q                   → mod_mul.sv
mod_add_traces   = []   # every (a + b) % q                   → mod_add.sv
mod_sub_traces   = []   # every (a - b) % q                   → mod_sub.sv
butterfly_traces = []   # every full butterfly (PE) operation  → pe0.sv / pe3.sv
ntt_stage_traces = []   # 256 coefficients snapshotted after each NTT stage
cbd_traces     = []   # every SamplePolyCBD_eta call       

def clear_all_traces():
    """Helper — call this before each test to ensure isolation."""
    mod_mul_traces.clear()
    mod_add_traces.clear()
    mod_sub_traces.clear()
    butterfly_traces.clear()
    ntt_stage_traces.clear()
    cbd_traces.clear()  

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

# === === === === ===  === === === === === ===
# === FIPS203 4.1: Cryptographic Functions ===
# === === === === ===  === === === === === ===

def H(b: bytes) -> bytes:
    return SHA3_256.new(b).digest()

def J(b: bytes) -> bytes:
    return SHAKE256.new(b).read(32)
    
def G(b: bytes) -> tuple[bytes, bytes]:
    h = SHA3_512.new(b).digest()
    return h[:32], h[32:]

def PRF_eta(eta: int, s: bytes, b: bytes) -> bytes:
    return SHAKE256.new(s + b).read(64*eta) # removed a line here
    
class XOF:
    @staticmethod
    def Init():
        return SHAKE128.new()
    @staticmethod
    def Absorb(ctx, data: bytes):
        ctx.update(data)
        return ctx
    @staticmethod
    def Squeeze(ctx, outlen_bytes: int):
        return ctx, ctx.read(outlen_bytes)

# === === === === === === === === === ===
# === FIPS203 4.2: General Algorithms ===
# === === === === === === === === === ===

# === 4.2.1: Conversion and Compression Algorithms ===

# FIPS203 Algorithm 3
def BitsToBytes(bits: list[int]) -> bytes:
    assert len(bits)%8 == 0
    out = bytearray(len(bits)//8)
    for i,bit in enumerate(bits):
        out[i>>3] |= (bit & 1) << (i & 7) # bitwise for out[i//8] += (bit % 2) << (i % 8)
    return bytes(out)
    
# FIPS203 Algorithm 4
def BytesToBits(B: bytes) -> list[int]:
    b = []
    for byte in B:
        for j in range(8):
            b.append(byte & 1)
            byte >>= 1
    return b

def Compress_d(x: list[int], d: int) -> list[int]:
    assert 1 <= d < 12
    def compress_coefficient(x2,d):
        return int(((1<<d) * x2 + q//2) // q) % (1<<d)
    return [compress_coefficient(i, d) for i in x]

def Decompress_d(y: list[int], d: int) -> list[int]:
    assert 1 <= d < 12
    def decompress_coefficient(y2,d):
        return int((q * y2 + (1<<d)//2) // (1<<d)) % q
    return [decompress_coefficient(i,d) for i in y]

# FIPS203 Algorithm 5
def ByteEncode_d(F: list[int], d: int) -> bytes:
    assert len(F)==256
    assert 1<=d<=12
    bits=[]
    if d < 12:
        m = 1 << d
        for a in F:
            assert 0<=a<m
            for j in range(d):
                bits.append(a & 1)      # b[i*d + j] <- a mod 2
                a = (a - (a & 1)) >> 1  # a <- (a - b)/2  (= a >>= 1)
    else:  # d == 12
        for a in F:
            assert 0<=a<q
            for j in range(12):
                bits.append(a & 1)      # b[i*d + j] <- a mod 2
                a = (a - (a & 1)) >> 1  # a <- (a - b)/2  (= a >>= 1)
    return BitsToBytes(bits)

# FIPS203 Algorithm 6
def ByteDecode_d(B: bytes, d: int) -> list[int]:
    assert 1 <= d <= 12
    assert len(B) * 8 == 256 * d  # B ∈ B^{32·d}
    bits = BytesToBits(B)
    m = (1 << d) if d < 12 else q
    F=[]
    for i in range(256):
        a = 0
        base = i * d
        for j in range(d):
            a += (bits[base + j] & 1) << j
        F.append(a % m)     # redundant for d<12, required for d=12
    return F

# === 4.2.1: Conversion and Compression Algorithms ===

# FIPS203 Algorithm 7
def SampleNTT(B: bytes) -> list[int]:
    assert len(B)==34 # B = seed32 || bytes(i) || bytes(j)
    ctx = XOF.Init()
    ctx = XOF.Absorb(ctx, B)
    a_hat=[0]*256
    j=0
    while j<256:
        ctx,C = XOF.Squeeze(ctx, 3)
        d1 = C[0] + 256*(C[1] & 0x0F)
        d2 = (C[1]>>4) + 16*C[2]
        if d1 < q:
            a_hat[j]=d1
            j+=1
        if d2 < q and j<256:
            a_hat[j]=d2
            j+=1
    return a_hat

# # FIPS203 Algorithm 8
# def SamplePolyCBD_eta(B: bytes, eta: int) -> list[int]:
#     assert eta in (2, 3)  # FIPS 203 uses eta ∈ {2,3}
#     assert len(B)==64*eta
#     f=[0]*256; t = BytesToBits(B)
#     for i in range(256):
#         x = sum(t[2*eta*i + j] for j in range(eta))
#         y = sum(t[2*eta*i + eta + j] for j in range(eta))
#         f[i] = (x - y) % q
#     return f
def SamplePolyCBD_eta(B: bytes, eta: int) -> list[int]:
    assert eta in (2, 3)
    assert len(B) == 64 * eta
    f = [0] * 256
    t = BytesToBits(B)
    for i in range(256):
        x = sum(t[2*eta*i + j] for j in range(eta))
        y = sum(t[2*eta*i + eta + j] for j in range(eta))
        f[i] = (x - y) % q

    # Track call index to distinguish S vs E vectors
    call_index = len(cbd_traces)
    cbd_traces.append({
        "call_index": call_index,
        "coeffs": list(f)
    })

    return f

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

# # FIPS203 Algorithm 9
# def NTT(f: list[int]) -> list[int]:
#     assert len(f) == 256
#     f_hat = list(f)
#     i = 1
#     length = 128
#     while length >= 2:
#         start = 0
#         while start < 256:
#             zeta = _BitRev7(i)
#             i += 1
#             for j in range(start, start + length):
#                 t = (zeta * f_hat[j + length]) % q
#                 f_hat[j + length] = (f_hat[j] - t) % q
#                 f_hat[j] = (f_hat[j] + t) % q
#             start += 2 * length
#         length //= 2
#     return f_hat

# Radix 2 for hardware comparison
# def NTT(f: list[int]) -> list[int]:
#     assert len(f) == 256
#     f_hat = list(f)
#     i = 1
#     length = 128
#     stage = 0

#     # Snapshot the raw input before any stage runs
#     ntt_stage_traces.append({
#         "stage":  "input",
#         "length": None,
#         "coeffs": list(f_hat)
#     })

#     while length >= 2:
#         start = 0
#         while start < 256:
#             zeta = _BitRev7(i)
#             i += 1
#             for j in range(start, start + length):

#                 # Snapshot inputs before the butterfly
#                 u_in = f_hat[j]
#                 v_in = f_hat[j + length]

#                 # --- Instrumented butterfly ---
#                 # t = zeta * v          → mod_mul.sv
#                 # u_out = u + t         → mod_add.sv
#                 # v_out = u - t         → mod_sub.sv
#                 t               = _log_mul(zeta, v_in)
#                 f_hat[j]        = _log_add(u_in, t)
#                 f_hat[j+length] = _log_sub(u_in, t)

#                 # Full PE transaction — maps directly to pe0.sv / pe3.sv test vector
#                 butterfly_traces.append({
#                     "direction": "fwd",
#                     "stage":     stage,
#                     "layer":     length,   # 128=stage0 ... 2=stage6
#                     "zeta":      zeta,
#                     "u_in":      u_in,
#                     "v_in":      v_in,
#                     "t":         t,        # intermediate mul result
#                     "u_out":     f_hat[j],
#                     "v_out":     f_hat[j + length],
#                 })

#             start += 2 * length

#         # Snapshot all 256 coefficients after this entire stage completes
#         ntt_stage_traces.append({
#             "stage":  stage,
#             "length": length,   # 128=stage0, 64=stage1, 32=stage2 ... 2=stage6
#             "coeffs": list(f_hat)
#         })

#         stage  += 1
#         length //= 2

#     return f_hat

def NTT(f: list[int]) -> list[int]:
    assert len(f) == 256
    a = list(f)

    OMEGA1_4 = 1729  # ζ^64 mod q — constant 4th primitive root of unity

    # Build R4NTT_ROM: 21 triplets (ω1, ω2, ω3), where ω3 = ω1*ω2 mod q
    # p=3 →  1 entry: ω2=_BitRev7(1),    ω1=_BitRev7(2)
    # p=2 →  4 entries: ω2=_BitRev7(4+k),  ω1=_BitRev7(8+2k)
    # p=1 → 16 entries: ω2=_BitRev7(16+k), ω1=_BitRev7(32+2k)
    R4NTT_ROM = []
    w2 = _BitRev7(1);  w1 = _BitRev7(2)
    R4NTT_ROM.append((w1, w2, (w1 * w2) % q))
    for k in range(4):
        w2 = _BitRev7(4 + k);  w1 = _BitRev7(8 + 2*k)
        R4NTT_ROM.append((w1, w2, (w1 * w2) % q))
    for k in range(16):
        w2 = _BitRev7(16 + k);  w1 = _BitRev7(32 + 2*k)
        R4NTT_ROM.append((w1, w2, (w1 * w2) % q))

    # OMEGA_ROM: 64 entries for the final Radix-2 pass
    OMEGA_ROM = [_BitRev7(64 + b) for b in range(64)]

    # Snapshot raw input
    ntt_stage_traces.append({"stage": "input", "length": None, "coeffs": list(a)})

    rom_idx = 0

    # Three Radix-4 passes: p = 3, 2, 1
    for p in range(3, 0, -1):
        stride   = 4 ** p   # 64 → 16 → 4
        pass_num = 4 - p    #  1 →  2 → 3

        for k in range(256 // (4 * stride)):
            omega1, omega2, omega3 = R4NTT_ROM[rom_idx];  rom_idx += 1

            for j in range(stride):
                m = 4 * k * stride + j

                r0 = (a[m]            + a[m + 2*stride] * omega2) % q
                r1 = (a[m]            - a[m + 2*stride] * omega2) % q
                r2 = (a[m + stride]   * omega1 + a[m + 3*stride] * omega3) % q
                r3 = (a[m + stride]   * omega1 - a[m + 3*stride] * omega3) % q

                a[m]            = (r0 + r2)            % q
                a[m + stride]   = (r0 - r2)            % q
                a[m + 2*stride] = (r1 + r3 * OMEGA1_4) % q
                a[m + 3*stride] = (r1 - r3 * OMEGA1_4) % q

        # Snapshot after each Radix-4 pass — matches ROM1 hardware checkpoint
        ntt_stage_traces.append({
            "stage":  f"r4_pass_{pass_num}",
            "pass":   pass_num,
            "length": stride,
            "coeffs": list(a)
        })

    # Final Radix-2 pass — matches ROM2 hardware checkpoint
    for j in range(0, 256, 4):
        omega = OMEGA_ROM[j // 4]
        u0 = a[j];    u1 = a[j + 1]
        v0 = a[j + 2] * omega % q
        v1 = a[j + 3] * omega % q
        a[j]     = (u0 + v0) % q
        a[j + 2] = (u0 - v0) % q
        a[j + 1] = (u1 + v1) % q
        a[j + 3] = (u1 - v1) % q

    ntt_stage_traces.append({
        "stage":  "r2_final",
        "pass":   4,
        "length": 2,
        "coeffs": list(a)
    })

    return a

# FIPS203 Algorithm 10
def NTT_inv(f_hat: list[int]) -> list[int]:
    assert len(f_hat) == 256
    f = list(f_hat)
    i = 127
    length = 2
    while length <= 128:
        start = 0
        while start < 256:
            zeta = _BitRev7(i)
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % q
                f[j + length] = (zeta * (f[j + length] - t)) % q
            start += 2 * length
        length *= 2
    for j in range(256):
        f[j] = (f[j] * 3303) % q
    return f

# FIPS203 Algorithm 12
def BaseCaseMultiply(a0: int, a1: int, b0: int, b1: int, gamma: int) -> (int,int):
    c0 = (a0 * b0 + a1 * b1 * gamma) % q
    c1 = (a0 * b1 + a1 * b0) % q
    return c0, c1

# FIPS203 Algorithm 11
def MultiplyNTTs(f_hat: list[int], g_hat: list[int]) -> list[int]:
    assert len(f_hat) == 256 and len(g_hat) == 256
    h_hat = [0] * 256
    for i in range(128):
        h_hat[2*i], h_hat[2*i + 1] = BaseCaseMultiply(
            f_hat[2*i],
            f_hat[2*i + 1],
            g_hat[2*i],
            g_hat[2*i + 1],
            _2BitRev7_1(i)
        )
    return h_hat
