import argparse
import logging
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="HD Wallet Analyzer for detecting vulnerabilities.")

    # Add arguments for seed, derivation path, and key reuse detection
    parser.add_argument("--seed", type=str, help="The HD wallet seed (hex encoded)", required=False)
    parser.add_argument("--derivation_path", type=str, help="The derivation path (e.g., m/44'/0'/0'/0)", required=False)
    parser.add_argument("--public_keys", type=str, help="Path to a file containing a list of public keys (one per line) to check for reuse.", required=False)
    parser.add_argument("--private_key_file", type=str, help="Path to PEM-encoded private key file", required=False)


    # Arguments for output and verbosity
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("--output", type=str, help="Output file for results.")

    return parser


def derive_key_from_seed(seed_hex, derivation_path):
     """
     Derives a private key from a seed and derivation path using BIP32.
     Simplified for demonstration. Not fully BIP32 compliant.

     Args:
         seed_hex (str): Hex encoded seed
         derivation_path (str): BIP32 derivation path.

     Returns:
         bytes: The derived private key as bytes.
     """
     try:
         seed = bytes.fromhex(seed_hex)
     except ValueError:
         logging.error("Invalid seed: Seed must be a hex encoded string.")
         return None

     path_components = derivation_path.split('/')
     if path_components[0] != 'm':
         logging.warning("Derivation path should start with 'm'.  This implementation assumes standard BIP32.")

     key = seed # In a real implementation this would be an HMAC based key derivation
     # The running value has to stay in its own variable. An earlier version
     # reused the name key for the Hash object and then tried key + bytes,
     # which raised TypeError on the first path component, so the seed mode
     # never produced a key at all.
     for component in path_components[1:]:
         # Simplified key derivation (NOT BIP32 standard)
         # In a real HDWallet, this involves HMAC-SHA512 and more complex steps.
         try:
             if "'" in component: #Indicates hardened derivation
                 component = component.replace("'","")
                 index = int(component) + 2**31  # Hardened key derivation
             else:
                 index = int(component)
         except ValueError:
             logging.error(f"Invalid derivation path component: {component!r}")
             return None

         #Simple, not secure derivation. Use only for demonstration.
         digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
         digest.update(key + index.to_bytes(4, 'big'))
         key = digest.finalize()

     return key  # Returns the derived "private key" bytes.



def check_key_reuse(private_key_hex, public_key_file):
    """
    Checks for key reuse by comparing the derived public key from the private key
    against a list of public keys in a file.

    Args:
        private_key_hex (str): The private key as a hex string.
        public_key_file (str): Path to the file containing public keys (one per line).

    Returns:
        bool: True if key reuse is detected, False otherwise.
    """
    try:
        private_key_bytes = bytes.fromhex(private_key_hex)
    except ValueError:
        logging.error("Invalid private key: Must be a hex encoded string.")
        return False

    try:
        private_value = int.from_bytes(private_key_bytes, 'big')

        # Derive the public key through the library's key constructor. The
        # earlier code multiplied the integer by a generator attribute the
        # curve object does not have, so this errored on every call and the
        # reuse check always reported False, matched or not.
        # derive_private_key also rejects values outside the curve order.
        public_key = ec.derive_private_key(private_value, ec.SECP256K1()).public_key()

        # Serialize the public key to hex
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )

        derived_public_key_hex = public_key_bytes.hex()


    except Exception as e:
        logging.error(f"Error deriving public key: {e}")
        return False


    try:
        with open(public_key_file, 'r') as f:
            for line in f:
                public_key = line.strip()
                if derived_public_key_hex == public_key:
                    logging.warning("Key reuse detected! Derived public key found in the public key list.")
                    return True
    except FileNotFoundError:
        logging.error(f"Public key file not found: {public_key_file}")
        return False
    except Exception as e:
        logging.error(f"Error reading public key file: {e}")
        return False

    return False


def analyze_hd_wallet(args):
    """
    Analyzes the HD wallet based on the provided arguments.

    Args:
        args (argparse.Namespace): The parsed command-line arguments.
    """
    results = []
    if args.seed and args.derivation_path:
        logging.info("Analyzing HD wallet...")
        derived_key = derive_key_from_seed(args.seed, args.derivation_path)
        if derived_key:
            derived_key_hex = derived_key.hex()
            logging.info(f"Derived Key (hex): {derived_key_hex}")
            results.append(f"Derived Key (hex): {derived_key_hex}")
            if args.public_keys:
                reused = check_key_reuse(derived_key_hex, args.public_keys)
                results.append(f"Key reuse detected: {reused}")

    elif args.private_key_file and args.public_keys:
          logging.info("Analyzing key reuse from private key file...")
          try:
              with open(args.private_key_file, 'rb') as key_file:
                  private_key = load_pem_private_key(
                      key_file.read(),
                      password=None,  # Add password handling if needed
                      backend=default_backend()
                  )
              # Feed the reuse check the key's own integer, not its DER
              # encoding: the earlier code hexed the whole PKCS8 blob and
              # used that as the private value, a number with no relation
              # to the key in the file.
              if not hasattr(private_key, "private_numbers"):
                  logging.error("Private key file does not hold an elliptic curve key.")
                  return results
              private_key_hex = private_key.private_numbers().private_value.to_bytes(32, 'big').hex()

              reused = check_key_reuse(private_key_hex, args.public_keys)
              results.append(f"Key reuse detected: {reused}")

          except FileNotFoundError:
              logging.error(f"Private key file not found: {args.private_key_file}")
          except Exception as e:
              logging.error(f"Error reading or processing private key file: {e}")

    else:
        logging.warning("Please provide both seed and derivation path or a private key file and a public key list to analyze.")

    return results



def main():
    """
    The main function of the HD Wallet Analyzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    results = analyze_hd_wallet(args)

    if not results:
        # Nothing was analyzed (missing argument pair, bad seed, missing
        # file). That used to exit 0, with only a log line to show for it.
        sys.exit(1)

    if args.output:
        # --output used to be acknowledged in a log line and never written.
        # The file now gets the same result lines the analysis produced.
        with open(args.output, "w") as f:
            f.write("\n".join(results) + "\n")
        logging.info(f"Results written to: {args.output}")


if __name__ == "__main__":
    main()