https://pq-crystals.org/kyber/data/kyber-specification-round3-20210131.pdf
B = set of all bytes
B^k = Byte array with k bytes
B^* = Byte stream of any length

BytesToBits(B[i]) = (b[i/8])/2^(i mod 8) mod 2

R = polynomial ring of all polynomials with degree less than n (256)
R_q = polynomial ring of all polynomials with degree less than n (256) and coefficients in mod q (3329)

mod^+ = mod with positive remainder (0 <= r' < a)
mod^+- = mod with positive or negative remainder

Algorithm 1: Parse Byte Stream (B^*) to Polynomal (R^n_q)
Input: Byte stream B^*
Output: NTT-representation ^a (accented a) member of R_q of a member of R_q

i = 0
j = 0
while j < n (256){
    d_1 = b[i] + 256 (b[i+1] mod^+ 16)
    d_2 = round(b[i+1]/16) + 16 * b[i+2]
    if d_1 < q (3329){
        ^a[j] = d_1
        j = j + 1
    }
    if d_2 < q (3329) && j < n (256){
        ^a[j] = d_2
        j = j + 1
    }
    i = i + 3
}
return ^a + ^a[1]X + ... + ^a[n-1]X^(n-1) (NTT Polynomial representation)
We have generated a list of coefficients for a polynomial

Algorithm 2: CBD (Centered Binomial Distribution) 
l = long n
Input: Byte array B^64*l (must be multiple of 64)
Output: Polynomial f member of R_q (degree less than n, coefficients in mod q)
B (B[0...(512*l)-1]) = BytesToBits(B)
for (i = 0; i < 256; i++){
    a = sum(from j = 0 to l-1: B[2*i*l+j])
    b = sum(from j = 0 to l-1: B[2*i*l+l+j])
    f[i] = a - b
}
return polynomial f (f[0] + f[1]X + ... + f[255]X^255)

Algorithm 3: Decode_l: B^32*l -> R_q
Input: Byte array B member of B^32*l
Output: Polynomial f member of R_q (degree less than n, coefficients in mod q)
B: (B[0...256*l-1]) = BytesToBits(B)
for (i = 0; i < 256; i++){
    f[i] = sum(from j = 0 to l-1: B[i*l+j]*2^j)
}
return polynomial f (f[0] + f[1]X + ... + f[255]X^255)

Algorithm 4: Kyber.CPAPKE.KeyGen()
Output: Secret Key sk member of B^(12*k*n/8)
Output: Public Key pk member of B^(12*k*n/8+32)
d = B^(32)
