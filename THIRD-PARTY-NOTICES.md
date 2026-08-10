# Third-party notices

`bsvz-proofs` is licensed under the MIT License (see `LICENSE`). It is a port of,
and byte-for-byte compatible with, the AnchorChain `privacy` package, and links
against the `bsvz` secp256k1 backend. Those components remain under their own
licenses:

## AnchorChain `privacy` — MIT

`bsvz-proofs` ports the logic, encodings, labels, and Fiat–Shamir construction of
the AnchorChain `privacy` TypeScript package. MIT obligations (attribution,
retention of the copyright/permission notice) apply to that lineage.

- Source: https://github.com/prof-faustus/anchorchain (packages/privacy)
- License: MIT

## `bsvz` — Open BSV License Version 5

`bsvz-proofs` links against `bsvz` (Zig secp256k1 backend), which is distributed
under the Open BSV License Version 5, granted by the BSV Association. Its
terms are conditioned and revocable and include the following requirements:

1. The text "© BSV Association," and the Open BSV License shall be included in
   all copies or substantial portions of the Software.
2. The Software, and any software that is derived from the Software or parts
   thereof, must only be used on the BSV Blockchains.

For the avoidance of doubt: the OBL v5 conditions attach to the `bsvz` code
itself. Whether merely linking `bsvz` makes a downstream project a derivative
work is a legal interpretation; if your deployment depends on this, obtain
professional advice.

- Source: https://github.com/b-open-io/bsvz
- License: Open BSV License Version 5 (full text at
  https://github.com/b-open-io/bsvz/blob/main/LICENSE)
