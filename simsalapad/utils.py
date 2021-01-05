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
import binascii

class utils(object):

    def splitBlocks(self, ciphertext, block_size):
        return [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]

    def xorForNextPadding(self, block, current_padding_position):
        for pad_reverse_position in range(1, current_padding_position + 1):
            block[-pad_reverse_position] ^= current_padding_position ^ current_padding_position + 1

    def xor(self, string_a, string_b):
        return bytes([a ^ b for a, b in zip(string_a, string_b)])

    def xorxor(self, string_a, string_b, string_c):
        return bytes([a ^ b ^ c for a, b, c in zip(string_a, string_b, string_c)])

    def block2Hex(self, block):
        if type(block) == list and type(block[0]) == int:
            return binascii.hexlify(bytes(block)).upper()
        elif type(block) == bytes:
            return binascii.hexlify(block).upper()
        elif type(block) == list and type(block[0][0]) == bytes:
            return binascii.hexlify(block[0][0]).upper()
