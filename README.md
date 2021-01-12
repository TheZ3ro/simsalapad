# simsalapad
Padding oracle attack made easy

## Installation

`pip install simsalapad`

## Usage as a library

Define an oracle function that accept a bytestring as input and return true if the padding is correct and false otherwise

```
def oracle(text):
    return offline_oracle(text)
```

Create a PaddingOracle object and pass the oracle function and the IV.  
**Note:** If the IV is not know, put a series of zeroes, this the resulting plaintext will have the first block corrupted.

```
p = simsalapad.PaddingOracle(iv=b'1111111111111111', oracle=oracle)
```

Assign an initial ciphertext to perform the padding oracle decryption on
```
p.initWithCiphertext(unhexlify("bdf784e982b35815d47ba17d24c0fbfd40a557989905ed4e1a86cd3919cf9b22"))
```

Start the actual attack
```
print(p.attack())
```
