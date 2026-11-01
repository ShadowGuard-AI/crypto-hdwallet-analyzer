import argparse
import hashlib
import hmac as hmac_module
import logging
import os
import struct
import sys

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# secp256k1 parameters
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
_HARDENED = 2 ** 31
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class KeyReuseCheckError(Exception):
    """Raised when the key reuse check could not be completed."""


def _point_add(p, q):
    # None stands for the point at infinity all through this file, so
    # adding it returns the other point unchanged.
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    # Same x and y values that cancel means the points are inverses, and
    # the sum is infinity. This has to be checked before the doubling
    # branch below, because a point with y == 0 would land here too and
    # the doubling formula would try to invert zero.
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p == q:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _point_mul(k, point=None):
    if point is None:
        point = _G
    # Double and add over the bits of k. result starts at infinity, so
    # k == 0 returns None, which callers treat as an invalid point.
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _ser_p(point):
    # Compressed form: x alone, with the prefix carrying the parity of y
    # so y can be recovered. Every hash, fingerprint, and comparison in
    # this file uses this form, never the uncompressed one.
    x, y = point
    prefix = b"\x03" if y % 2 else b"\x02"
    return prefix + x.to_bytes(32, 'big')


def _hash160(data):
    sha = hashlib.sha256(data).digest()
    ripe = hashlib.new('ripemd160')
    ripe.update(sha)
    return ripe.digest()


def _base58check(payload):
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + checksum
    num = int.from_bytes(data, 'big')
    encoded = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = _BASE58_ALPHABET[rem] + encoded
    # The integer conversion above drops leading zero bytes, and in
    # base58check each one is a literal "1". I count them off the
    # original bytes, before that information is gone.
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + encoded


def _fingerprint(point):
    return _hash160(_ser_p(point))[:4]


def _master_node(seed):
    digest = hmac_module.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    private_value = int.from_bytes(digest[:32], 'big')
    if private_value == 0 or private_value >= _N:
        raise ValueError("Seed produced an invalid master key.")
    return {
        "private": private_value,
        "chain": digest[32:],
        "depth": 0,
        "parent_fingerprint": b"\x00\x00\x00\x00",
        "child_number": 0,
        "public_point": _point_mul(private_value),
    }


def _ckd_priv(node, index):
    # The split here is the whole point of hardened derivation: a
    # hardened step hashes the private key itself (with a zero byte in
    # front to keep the length equal), so it cannot be reproduced from
    # the parent public key. A normal step hashes the public point,
    # which is what lets _ckd_pub mirror it from an xpub.
    if index >= _HARDENED:
        data = b"\x00" + node["private"].to_bytes(32, 'big') + struct.pack(">L", index)
    else:
        data = _ser_p(node["public_point"]) + struct.pack(">L", index)
    digest = hmac_module.new(node["chain"], data, hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], 'big')
    if tweak >= _N:
        raise ValueError("Child derivation produced an invalid tweak.")
    child_private = (tweak + node["private"]) % _N
    if child_private == 0:
        raise ValueError("Child derivation produced an invalid key.")
    return {
        "private": child_private,
        "chain": digest[32:],
        "depth": node["depth"] + 1,
        "parent_fingerprint": _fingerprint(node["public_point"]),
        "child_number": index,
        "public_point": _point_mul(child_private),
    }


def _ckd_pub(node, index):
    if index >= _HARDENED:
        raise ValueError("Cannot derive a hardened child from a public key.")
    data = _ser_p(node["public_point"]) + struct.pack(">L", index)
    digest = hmac_module.new(node["chain"], data, hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], 'big')
    if tweak >= _N:
        raise ValueError("Child derivation produced an invalid tweak.")
    child_point = _point_add(_point_mul(tweak), node["public_point"])
    if child_point is None:
        raise ValueError("Child derivation produced an invalid point.")
    return {
        "private": None,
        "chain": digest[32:],
        "depth": node["depth"] + 1,
        "parent_fingerprint": _fingerprint(node["public_point"]),
        "child_number": index,
        "public_point": child_point,
    }


def serialize_node(node, private=True):
    if private:
        if node["private"] is None:
            raise ValueError("Node has no private key.")
        version = bytes.fromhex("0488ADE4")
        key_data = b"\x00" + node["private"].to_bytes(32, 'big')
    else:
        version = bytes.fromhex("0488B21E")
        key_data = _ser_p(node["public_point"])
    payload = (version + bytes([node["depth"]]) + node["parent_fingerprint"]
               + struct.pack(">L", node["child_number"]) + node["chain"] + key_data)
    return _base58check(payload)


def parse_derivation_path(derivation_path):
    if not derivation_path:
        raise ValueError("Derivation path is empty.")
    parts = derivation_path.split('/')
    if parts[0] != 'm':
        raise ValueError("Derivation path must start with 'm'.")
    indices = []
    for component in parts[1:]:
        if component == "":
            raise ValueError(f"Invalid derivation path component: {component!r}")
        hardened = False
        name = component
        if name[-1] in ("'", "h", "H"):
            hardened = True
            name = name[:-1]
        try:
            value = int(name)
        except ValueError:
            raise ValueError(f"Invalid derivation path component: {component!r}")
        # The range check runs on the bare value, before the hardened
        # offset is added, so the largest accepted index plus the offset
        # still fits the 4 byte field _ckd_priv packs it into.
        if value < 0 or value >= _HARDENED:
            raise ValueError(f"Derivation path component out of range: {component!r}")
        indices.append(value + _HARDENED if hardened else value)
    return indices


def derive_bip32_node(seed_hex, derivation_path):
    try:
        seed = bytes.fromhex(seed_hex)
    except ValueError:
        raise ValueError("Invalid seed: Seed must be a hex encoded string.")
    node = _master_node(seed)
    for index in parse_derivation_path(derivation_path):
        node = _ckd_priv(node, index)
    return node


def public_key_hex_from_private(private_value):
    if not (1 <= private_value < _N):
        raise ValueError("Private key value is outside the secp256k1 curve order.")
    return _ser_p(_point_mul(private_value)).hex()


def setup_argparse():
    parser = argparse.ArgumentParser(description="HD Wallet Analyzer for detecting vulnerabilities.")
    parser.add_argument("--seed", type=str, help="The HD wallet seed (hex encoded)", required=False)
    parser.add_argument("--derivation_path", type=str, help="The derivation path (e.g., m/44'/0'/0'/0)", required=False)
    parser.add_argument("--public_keys", type=str, help="Path to a file containing a list of public keys (one per line) to check for reuse.", required=False)
    parser.add_argument("--private_key_file", type=str, help="Path to PEM-encoded private key file", required=False)
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("--output", type=str, help="Output file for results. By default the file holds the derived public key and the reuse result, not the derived private key. See --include-private-key.")
    parser.add_argument("--include-private-key", action="store_true", help="Include the derived private key in the output file. The output file is then created with 0600 permissions and a warning is printed that the file holds key material.")
    return parser


def derive_key_from_seed(seed_hex, derivation_path):
    """
    Derives a private key from a seed and derivation path using BIP32.
    The master key is HMAC-SHA512 with the key 'Bitcoin seed' over the
    seed. Each child step uses HMAC-SHA512 with the chain code, with
    hardened and normal derivation as the path marks, on secp256k1.

    Args:
        seed_hex (str): Hex encoded seed
        derivation_path (str): BIP32 derivation path.

    Returns:
        bytes: The derived private key as bytes, or None on error.
    """
    try:
        node = derive_bip32_node(seed_hex, derivation_path)
    except ValueError as e:
        logging.error(str(e))
        return None
    return node["private"].to_bytes(32, 'big')


def check_key_reuse(private_key_hex, public_key_file):
    """
    Checks for key reuse by comparing the derived public key from the
    private key against a list of public keys in a file.

    Returns:
        bool: True if key reuse is detected, False if it is not.

    Raises:
        KeyReuseCheckError: If the private value is rejected or the
            list file cannot be read, so a check that never ran is
            not reported as a clear check.
    """
    try:
        private_key_bytes = bytes.fromhex(private_key_hex)
    except ValueError:
        raise KeyReuseCheckError("Invalid private key: Must be a hex encoded string.")
    private_value = int.from_bytes(private_key_bytes, 'big')
    try:
        derived_public_key_hex = public_key_hex_from_private(private_value)
    except Exception as e:
        raise KeyReuseCheckError(f"Error deriving public key: {e}")
    try:
        with open(public_key_file, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        raise KeyReuseCheckError(f"Public key file not found: {public_key_file}")
    except Exception as e:
        raise KeyReuseCheckError(f"Error reading public key file: {e}")
    # Exact string match against the compressed hex form this file
    # derives. A list holding uncompressed keys, or the same key in
    # upper case, will read as no reuse even when the key is in it. I
    # leave that strictness in and name it here rather than guessing at
    # formats the file might contain.
    for line in lines:
        if derived_public_key_hex == line.strip():
            logging.warning("Key reuse detected! Derived public key found in the public key list.")
            return True
    return False


def analyze_hd_wallet(args):
    results = []
    if args.seed and args.derivation_path:
        logging.info("Analyzing HD wallet...")
        try:
            node = derive_bip32_node(args.seed, args.derivation_path)
        except ValueError as e:
            logging.error(str(e))
            return results
        derived_key_hex = node["private"].to_bytes(32, 'big').hex()
        derived_public_hex = _ser_p(node["public_point"]).hex()
        logging.info(f"Derived public key (hex): {derived_public_hex}")
        results.append(f"Derived public key (hex): {derived_public_hex}")
        results.append(f"Extended public key (xpub): {serialize_node(node, private=False)}")
        if getattr(args, "include_private_key", False):
            results.append(f"Derived Key (hex): {derived_key_hex}")
        if args.public_keys:
            try:
                reused = check_key_reuse(derived_key_hex, args.public_keys)
                results.append(f"Key reuse detected: {reused}")
            except KeyReuseCheckError as e:
                logging.error(str(e))
                results.append("Key reuse check: not checked")
    elif args.private_key_file and args.public_keys:
        logging.info("Analyzing key reuse from private key file...")
        try:
            with open(args.private_key_file, 'rb') as key_file:
                private_key = load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            if not hasattr(private_key, "private_numbers"):
                logging.error("Private key file does not hold an elliptic curve key.")
                return results
            private_key_hex = private_key.private_numbers().private_value.to_bytes(32, 'big').hex()
            try:
                reused = check_key_reuse(private_key_hex, args.public_keys)
                results.append(f"Key reuse detected: {reused}")
            except KeyReuseCheckError as e:
                logging.error(str(e))
                results.append("Key reuse check: not checked")
        except FileNotFoundError:
            logging.error(f"Private key file not found: {args.private_key_file}")
        except Exception as e:
            logging.error(f"Error reading or processing private key file: {e}")
    else:
        logging.warning("Please provide both seed and derivation path or a private key file and a public key list to analyze.")
    return results


def main():
    parser = setup_argparse()
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")
    results = analyze_hd_wallet(args)
    if not results:
        sys.exit(1)
    check_failed = any("not checked" in line for line in results)
    if args.output:
        include_private = getattr(args, "include_private_key", False) and any(
            line.startswith("Derived Key (hex):") for line in results)
        if include_private:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(results) + "\n")
            try:
                os.chmod(args.output, 0o600)
            except OSError:
                pass
            logging.warning("Warning: the output file now holds private key material. Keep it private.")
            logging.info(f"Results written to: {args.output}")
        else:
            with open(args.output, "w") as f:
                f.write("\n".join(results) + "\n")
            logging.info(f"Results written to: {args.output}")
    elif getattr(args, "include_private_key", False):
        logging.warning("Warning: --include-private-key was given without --output, so no private key was written to a file.")
    if check_failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
