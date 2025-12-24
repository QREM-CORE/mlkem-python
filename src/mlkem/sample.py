def byte_to_bit_array(byte_array: bytes):
    bit_array = []
    for byte in byte_array:
        for i in range(8):
            bit = (byte >> i) & 1
            bit_array.append(bit)
    return bit_array

def sample_poly_cbd(B: bytes, eta: int, Q: int):
    if len(B) != 64 * eta:
        raise ValueError("Invalid length of B")
            
    bit_array=byte_to_bit_array(B)  # Placeholder for the actual bit array input
    f = [0] * 256
    # Implement the sampling from a centered binomial distribution (CBD)
    for i in range(0,256):
       x = 0
       y = 0
       for j in range(eta):
            x += bit_array[2 * i * eta + j]
            y += bit_array[2 * i * eta + eta + j]    
        f[i] = (x - y) % Q
    return f