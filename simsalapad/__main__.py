#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import base64

from sys import exit
from ast import literal_eval

from simsalapad import PaddingOracle, IVRecover, VERSION

def main():
    parser = argparse.ArgumentParser(prog='simsalapad', description="Padding Oracle attack & IV recover tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--padding', action='store_true', help='Do a padding oracle attack', default=False,
                       dest="padding")
    group.add_argument('--iv-recover', action='store_true', help='Try to find a valid IV for decryption routine',
                       default=False, dest="ivfinder")
    parser.add_argument("-p", metavar="PATH", help="Path to the oracle (python file)", type=str, required=False,
                        dest="path")
    parser.add_argument("-c", metavar="CIPHERTEXT", help="Ciphertext that should be cracked", type=str, required=False,
                        dest="ciphertext")
    parser.add_argument("-bs", metavar="BLOCK SIZE", help="Set the size for each block", type=int, dest="block_size",
                        required=False)
    parser.add_argument("-b", action="store_true", help="Base64 decode the ciphertext before start", default=False,
                        dest="base64", required=False)
    parser.add_argument("-e", metavar="PLAINTEXT", help="Encrypt a custom message", type=str, required=False,
                        dest="encrypt")
    parser.add_argument('-V', '--version', action='version', version='%(prog)s v' + VERSION)
    args = parser.parse_args()
    if args.path:
        try:
            if args.padding:
                if args.block_size:
                    padding_oracle = PaddingOracle(block_size=args.block_size, oracle_path=args.path)
                else:
                    padding_oracle = PaddingOracle(oracle_path=args.path)
                padding_oracle.info("Starting bruteforce...")
                if args.ciphertext:
                    if args.base64:
                        try:
                            args.ciphertext = base64.b64decode(args.ciphertext)
                        except TypeError:
                            padding_oracle.error("Please insert a valid base64")
                            exit(-1)
                    else:
                        args.ciphertext = literal_eval(args.ciphertext)
                    padding_oracle.initWithCiphertext(args.ciphertext)
                else:
                    parser.error("You must use -c switch while checking for padding oracle!")
                padding_oracle.attack()
            else:
                if args.block_size:
                    iv_recover = IVRecover(block_size=args.block_size, decrypter_path=args.path)
                else:
                    iv_recover = IVRecover(decrypter_path=args.path)
                iv_recover.attack()
        except Exception as e:
            if args.padding:
                padding_oracle.error("Something goes wrong => {0}".format(e))
            else:
                iv_recover.error("Something goes wrong => {0}".format(e))
    else:
        parser.error("You must use -p switch while checking for padding oracle or iv-recover!")
if __name__ == "__main__":
    main()
