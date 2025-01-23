"""
MIT License (https://opensource.org/license/mit)

Copyright 2025 Koh Wei Jie <contact@kohweijie.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import sys
import varint
import requests
import multibase
from secp256k1 import PublicKey
from eth_utils import keccak, to_checksum_address


PDS_URL = "https://api.bsky.app"
RESOLVE_HANDLE_PATH = "/xrpc/com.atproto.identity.resolveHandle?handle="
PLC_URL = "https://plc.directory/"


def extract_secp256k1_pubkey(multibase_pub: str) -> bytes:
    # Decode from multibase (e.g. base58btc if it starts with 'z')
    raw_data = multibase.decode(multibase_pub)

    # Read the varint code at the start (this should be 0xe7 for secp256k1-pub)
    offset = 0
    code = varint.decode_bytes(raw_data[offset:])
    offset += len(varint.encode(code))

    if code != 0xe7:
        raise ValueError(
            f"Not a secp256k1-pub multicodec: expected 0xe7, got {hex(code)}."
        )

    # The remainder should be the actual secp256k1 public key bytes (33 or 65)
    pubkey_bytes = raw_data[offset:]

    return pubkey_bytes


def multibase_secp256k1_to_eth_address(multibase_pub: str) -> str:
    # Extract raw secp256k1 pubkey bytes
    pubkey_bytes = extract_secp256k1_pubkey(multibase_pub)

    if len(pubkey_bytes) != 33:
        raise ValueError("Invalid multibase-encoded public key; should produce a 33-byte result")
    pubkey = PublicKey(pubkey_bytes, raw=True)
    uncompressed_pubkey = pubkey.serialize(compressed=False)

    if len(uncompressed_pubkey) != 65:
        raise ValueError("Error in decompressing public key; should produce a 65-byte result")

    # Drop the 0x04 prefix and keccak-hash the 64-byte x||y
    pubkey_xy = uncompressed_pubkey[1:]
    keccak_hash = keccak(pubkey_xy)

    # The Ethereum address is the last 20 bytes the hash
    raw_addr = keccak_hash[-20:]

    return to_checksum_address(raw_addr)


def main():
    try:
        handle_or_did = input("Enter the user's ATProto handle or DID: ")
        did = None

        if handle_or_did.startswith("did:"):
            did = handle_or_did
        else:
            json = requests.get(PDS_URL + RESOLVE_HANDLE_PATH + handle_or_did).json()
            if "did" in json.keys():
                did = json["did"]
            else:
                raise ValueError("Invalid handle: " + handle_or_did)

        # Fetch the repo description
        json = requests.get(PLC_URL + did).json()

        # Fetch their service endpoint(s)
        endpoints = []
        if "service" in json.keys():
            for service in json["service"]:
                if "serviceEndpoint" in service.keys():
                    endpoints.append(service["serviceEndpoint"])
        else:
            print("Warning: could not find the 'service' field in the repo description. Be careful!")

        is_hosted = False
        if len(endpoints) == 0:
            print("Warning: the user's repo does not list any service endpoints. Be careful!")
        else:
            for endpoint in endpoints:
                if endpoint.endswith("host.bsky.network"):
                    is_hosted = True
                    break
        if is_hosted:
            print("Warning: the user's repo is probably hosted by Bluesky PBC, and most likely don't own their private key(s). Do not send funds to them if you are unsure.")
        else:
            print("Warning: only send funds to this user if you are sure they exclusively own their private key(s).")

        multibase_keys = []
        if "verificationMethod" in json.keys():
            pass
        else:
            raise ValueError("Unable to query " + PLC_URL + did)

        for key in json["verificationMethod"]:
            if "publicKeyMultibase" in key.keys():
                multibase_keys.append(key["publicKeyMultibase"])

        eth_addresses = []
        for key in multibase_keys:
            eth_address = multibase_secp256k1_to_eth_address(key)
            eth_addresses.append(eth_address)

        if len(eth_addresses) == 0:
            raise ValueError("Error: no public keys found for this user")
        elif len(eth_addresses) == 1:
            print("Ethereum Address:", eth_addresses[0])
        else:
            print("This user has multiple public keys. Their associated Ethereum addresses are:")
            for eth_address in eth_addresses:
                print(eth_address)
    except ValueError as e:
        print("Error:", e)


if __name__ == "__main__":
    main()
