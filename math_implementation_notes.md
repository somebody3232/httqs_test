https://pq-crystals.org/kyber/data/kyber-specification-round3-20210131.pdf
B = set of all bytes
B^k = Byte array with k bytes
B^* = Byte stream of any length

BytesToBits(B[i]) = (b[i/8])/2^(i mod 8) mod 2

R = polynomial ring of all polynomials with degree less than n (256)
R_q = polynomial ring of all polynomials with degree less than n (256) and coefficients in mod q (3329)

mod+ = mod with positive remainder (0 <= r' < a)
mod+- = mod with positive or negative remainder

PRF: pseudorandom function B^32 x B -> B^* PRF(s, b) = SHAKE-256(s||b)
XOF: extendable output function B^* x B x B -> B^* = SHAKE-128

Hash Functions
H: B^* -> B^32 = SHA3-256
G: B^* -> B^32 x B^32 = SHA3-512

Key Derivative Function KDF: B^* -> B^* = SHAKE-256

Compress_q(x, d) = round(((2^d)/q)*x) mod+ 2^d
Decompress_q(x, d) = round((q/(2^d))*x) 

∈ = element/member of

# Algorithm 1: Parse Byte Stream (B^*) to Polynomal (R^n_q)
##### Input: Byte stream B^*
##### Output: NTT-representation â member of R_q of a member of R_q

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
return â + â[1]X + ... + â[n-1]X^(n-1) (NTT Polynomial representation)

We have generated a list of coefficients for a polynomial

# Algorithm 2: CBD(ŋ, B) (Centered Binomial Distribution) 
[l = ŋ]
##### Input: Byte array B^64*ŋ (must be multiple of 64)
##### Output: Polynomial f member of R_q (degree less than n, coefficients in mod q)
B (B[0...(512*ŋ)-1]) = BytesToBits(B)
for (i = 0; i < 256; i++){
    a = sum(from j = 0 to ŋ-1: B[2*i*ŋ+j])
    b = sum(from j = 0 to ŋ-1: B[2*i*ŋ+ŋ+j])
    f[i] = a - b
}
return polynomial f (f[0] + f[1]X + ... + f[255]X^255)

# Algorithm 3: Decode_l: B^32*l -> R_q
##### Input: Byte array B member of B^32*l
##### Output: Polynomial f member of R_q (degree less than n, coefficients in mod q)
B: (B[0...256*l-1]) = BytesToBits(B)
for (i = 0; i < 256; i++){
    f[i] = sum(from j = 0 to l-1: B[i*l+j]*2^j)
}
return polynomial f (f[0] + f[1]X + ... + f[255]X^255)

Encode_l: R_q -> B^32*l (inverse of Decode_l)

# Algorithm 4: Kyber.CPAPKE.KeyGen()
##### Output: Secret Key sk member of B^(12*k*n/8)
##### Output: Public Key pk member of B^(12*k*n/8+32)
ŋ1 (for Kyber 768) = 2
ŋ2 = 2
k (for Kyber 768) = 3
Â = [k][k] matrix of polynomials in R_q
s = [k] vector of polynomials in R_q
e = [k] vector of polynomials in R_q
d <- [fancy set/dist thing] B^(32)
(p, σ) = G(d) // See hash functions
N = 0
// Generate matrix Â ∈ R_q^(k×k) in NTT domain
for (i = 0; i < k; i++){
    for (j = 0; j < k; j++){
         Â[i][j] = Parse(XOF(p, j, i))
    }
}
// Sample s ∈ R_q^k from B_l1
for (i = 0; i < k; i++){
    s[i] = CBD_ŋ1(PRF(σ, N))
    N++
}
// Sample e ∈ R_q^k from B_l1
for (i = 0; i < k; i++){
    e[i] = CBD_ŋ1(PRF(σ, N))
    N++
}
ŝ = NTT(s)
ê = NTT(e)
^t = Â ◦ ŝ + ^e
// pk = As + e
pk = (Encode_12(^t mod+ q)|| p) // the || operator is concatenation
sk = Encode_12(ŝ mod+ q)
return (pk, sk)

# Algorithm 5: Kyber.CPAPKE.Enc(pk, m, r): Encryption
##### Input: Public Key pk ∈ B^(12*k*n/8+32)
##### Input: Message m ∈ B^32
##### Input: Random coins r ∈ B^32
##### Output: Ciphertext c ∈ B^(d_u*l*n/8 + d_v*n/8) (Kyber768: d_u = 10, d_v = 4)
N = 0
^t = Decode_12(pk)
p = pk + 12 * k * n/8
// Generate matrix Â ∈ R_q^(k×k) in NTT domain
for (i = 0; i < k; i++){
    for (j = 0; j < k; j++){
         Â^T[i][j] = Parse(XOF(p, i, j))
    }
}
// Sample r ∈ R_q^k from B_ŋ1
for (i = 0; i < k; i++){
    r[i] = CBD_ŋ1(PRF(r, N))
    N++
}
// Sample e1 ∈ R_q^k from B_ŋ2
for (i = 0; i < k; i++){
    e1[i] = CBD_ŋ2(PRF(r, N))
    N++
}
// Sample e2 ∈ R_q^k from B_ŋ2
e2 = CBD_ŋ2(PRF(r, N))
^r = NTT(r)
// u = A^T r + e1
u = NTT^-1(Â^T ◦ ^r)+e1
// v = t^T r + e2 + Decompress_q(m, 1)
v = NTT^-1(^t^T ◦ ^r)+e2 + Decompress_q(Decode_1(m), 1)
c1 = Encode_d_u(Compress_q(u, d_u))
c2 = Encode_d_v(Compress_q(v, d_v))
// c = (Compress_q(u, d_u), Compress_q(v, d_v))
return c = (c1||c2)