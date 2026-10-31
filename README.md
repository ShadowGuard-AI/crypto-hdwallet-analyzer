![Banner](banner.png)

# crypto-hdwallet-analyzer
Scans Hierarchical Deterministic (HD) wallets for weak or compromised seeds, derivation paths, and key reuse, using real BIP32 derivation: the master key is HMAC-SHA512 with the key Bitcoin seed over the seed, the chain code is carried through hardened and normal child derivation on secp256k1, and paths use the m/x/y/z forms with the apostrophe hardened marker (for example m/44'/0'/0'/0). The derived keys are the keys a BIP32 wallet derives for that seed and path. This tool does not derive Ethereum addresses. Detects potential vulnerabilities arising from poor key management practices. - Focused on Basic cryptographic operations

## Install
`git clone https://github.com/ShadowStrikeHQ/crypto-hdwallet-analyzer`

## Usage
`./crypto-hdwallet-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `--seed`: No description provided
- `--derivation_path`: The derivation path (e.g., m/44
- `--public_keys`: No description provided
- `--private_key_file`: Path to PEM-encoded private key file
- `--verbose`: Enable verbose output.
- `--output`: Output file for results. By default the file holds the derived public key and the key reuse result, not the derived private key. The console log also shows the derived public key, not the raw private key.
- `--include-private-key`: Include the derived private key in the output file. Only with this flag is the private key written into the output file. The file is then created with 0600 permissions and a warning line prints that the file now holds key material.

## License
Copyright (c) ShadowStrikeHQ
