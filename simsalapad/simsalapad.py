"""
The MIT License (MIT)

Copyright (c) 2016

    The Zero <io@thezero.org>
    Daniele Linguaglossa <danielelinguaglossa@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import sys

from pathlib import Path
from importlib import import_module

from simsalapad.utils import utils

__all__ = ["PaddingOracle", "IVRecover"]

class IVRecover(utils):
    _decrypter = None
    _regex = None
    _decrypter_module = None
    _path = None
    _as_library = False
    _block_size = 0

    def __init__(self, block_size=16, decrypter_path=None, regex=None, decrypter=None):
        self._setBlockSize(block_size)
        if decrypter_path is not None:
            self._path = decrypter_path
        else:
            if decrypter is not None:
                if callable(decrypter):
                    self._decrypter = decrypter
                else:
                    raise Exception("Decrypter must be a method")
            else:
                raise Exception("You must specify a decrypter method")

    def error(self, text):
        sys.stderr.write("[ERROR] {0}\n".format(text))

    def info(self, text):
        sys.stdout.write("[INFO] {0}\n".format(text))

    def _load_decrypter(self, path):
        path = Path(path).resolve()
        sys.path.append(str(path.parent))
        try:
            self._decrypter_module = import_module(path.name[:-3])
            self._decrypter = self._decrypter_module.decrypt
        except ImportError:
            if not self._as_library:
                self.error("Your decrypter module must implement a decrypt method!")
            sys.exit(-1)

    def _setBlockSize(self, size):
        self._block_size = size

    def attack(self):
        if self._regex is None and self._decrypter is None:
            self._load_decrypter(self._path)
        else:
            self._as_library = True

        to_crypt = "\x00" * (self._block_size * 2)
        result = self._decrypter(to_crypt)
        blocks = self.splitBlocks(result, self._block_size)
        IV = self.xorxor(blocks[0], blocks[1], b"\x00" * self._block_size)
        if self._as_library:
            return IV
        else:
            self.info("Found IV: {0}".format(IV))


class PaddingOracle(utils):
    _plaintext = b""
    _oracle = None
    _IV = None
    _oracle_module = None
    _path = None
    _as_library = False
    _ciphertext = b""
    _intermediate_blocks = []

    def __init__(self, block_size=16, oracle_path=None, iv=None, oracle=None):
        self._setBlockSize(block_size)
        if oracle_path is not None:
            self._path = oracle_path
        else:
            if iv is not None and oracle is not None:
                if type(iv) == list and len(iv) > 0:
                    self._IV = iv
                elif type(iv) == bytes and len(iv) % self._block_size == 0:
                    self._IV = list(iv)
                else:
                    raise Exception("IV object must be a list of integers with len greater than 0, or a bytestring multiple of {} bytes".format(self._block_size))
                if callable(oracle):
                    self._oracle = oracle
                else:
                    raise Exception("Oracle object must be a method")
            else:
                raise Exception("You must specify an IV and an oracle method")

    def error(self, text):
        sys.stderr.write("[ERROR] {0}\n".format(text))

    def info(self, text):
        sys.stdout.write("[INFO] {0}\n".format(text))

    def _remove_padding(self, data):
        if 0 < int(data[-1]) <= 0x10:
            if data[-int(data[-1]):] != bytes([data[-1]]) * int(data[-1]):
                return False
            return data[:-int(data[-1])]
        return data

    def _load_oracle(self, path):
        path = Path(path).resolve()
        sys.path.append(str(path.parent))
        try:
            self._oracle_module = import_module(path.name[:-3])
            if "oracle" in dir(self._oracle_module):
                if callable(self._oracle_module.oracle):
                    self._oracle = self._oracle_module.oracle
                else:
                    self.error("Your oracle method must be a function!")
                    sys.exit(-1)
            else:
                self.error("Please define an oracle method!")
                sys.exit(-1)
            if "IV" in dir(self._oracle_module):
                if type(self._oracle_module.IV) == bytes:
                    self._IV = list(self._oracle_module.IV)
                else:
                    self._IV = self._oracle_module.IV
            else:
                self.error("Please define an IV vector!")
                sys.exit(-1)
        except ImportError:
            if not self._as_library:
                self.error("Your oracle module must implement an IV and an oracle method!")
            sys.exit(-1)

    def _setBlockSize(self, size):
        self._block_size = size

    def _crack_block(self, org_previous_block, next_block, oracle):
        dummy_block = list([0] * 16)
        half_plain = b""
        intermediate = []
        for reverse_position in range(1, len(next_block) + 1):
            for byte_guess in range(0, 256):
                dummy_block[-reverse_position] = byte_guess
                tmp = bytes(dummy_block) + bytes(next_block)
                if oracle(tmp):
                    intermediate = [byte_guess] + intermediate
                    half_plain = bytes([reverse_position ^ org_previous_block[-reverse_position] ^ byte_guess]) + half_plain
                    self.xorForNextPadding(dummy_block, reverse_position)
                    break
        return half_plain, self.block2Hex(dummy_block)

    def initWithCiphertext(self, ciphertext):
        self._ciphertext = ciphertext

    def _find_cipher_for_text(self, intermediate_block, org_previous_block, next_block, text_block):
        raise NotImplementedError("Coming soon")

    def encrypt_custom(self, text):
        raise NotImplementedError("Coming soon")

    def attack(self):
        if self._IV is None and self._oracle is None:
            self._load_oracle(self._path)
        else:
            self._as_library = True
        blocks = self.splitBlocks(self._ciphertext, self._block_size)
        self._org_cipher = [self._IV] + blocks
        for i in range(0, len(self._org_cipher) - 1):
            plain, intermediate = self._crack_block(list(self._org_cipher[i]), list(self._org_cipher[i + 1]), self._oracle)
            self._plaintext += plain
            self._intermediate_blocks.append(intermediate)
        if self._as_library:
            return self._remove_padding(self._plaintext)
        else:
            for i in range(0, len(self._org_cipher[:-1])):
                self.info("Start block-{0}: {1}".format(i, self.block2Hex(self._org_cipher[i])))
            for i in range(0, len(self._intermediate_blocks)):
                self.info("Intermediate block-{0}: {1}".format(i, self._intermediate_blocks[i]))
            self.info("Plaintext recovered: {0}".format(self._remove_padding(self._plaintext)))
