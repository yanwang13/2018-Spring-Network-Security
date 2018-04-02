# 2018-Spring-Network-Security

## Project1: Hacking the Cipher (Chosen Ciphertext Attack)
- choose X where X is relatively prime to public key n
- create Y = C*X^e mod n
- get Z = decrypted Y
- Z = Y^d = (C * X^e)^d = C^d * X^(e * d) = C^d * X = P^(e * d) * X = P* X mod n
- find out the modular inverse of X
- P = Z*(inverse_x) mod n
