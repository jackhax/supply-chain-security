"""
This module provides functionality for Merkle tree hash calculations 
according to RFC 6962. It includes classes and functions for hashing 
leaves, nodes, verifying consistency and inclusion proofs, and 
computing leaf hashes.
"""

import hashlib
import binascii
import base64

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1


class Hasher:
    """Hasher class to create and manage hash operations."""

    def __init__(self, hash_func=hashlib.sha256):
        self.hash_func = hash_func

    def new(self):
        """Creates a new hash object."""
        return self.hash_func()

    def empty_root(self):
        """Returns the hash of an empty root."""
        return self.new().digest()

    def hash_leaf(self, leaf):
        """Hashes a leaf using the RFC 6962 specification."""
        h = self.new()
        h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        h.update(leaf)
        return h.digest()

    def hash_children(self, left, right):
        """Hashes two child nodes."""
        h = self.new()
        b = bytes([RFC6962_NODE_HASH_PREFIX]) + left + right
        h.update(b)
        return h.digest()

    def size(self):
        """Returns the size of the hash output."""
        return self.new().digest_size


# DefaultHasher is a SHA256 based LogHasher
DefaultHasher = Hasher(hashlib.sha256)


def verify_consistency(hasher, size1, size2, proof, root1, root2):
    """Verifies the consistency between two root hashes."""
    try:
        root1 = bytes.fromhex(root1)
        root2 = bytes.fromhex(root2)
    except ValueError:
        print('Invalid root(s)')
        return
    bytearray_proof = [bytes.fromhex(elem) for elem in proof]

    if size2 < size1:
        raise ValueError(f"size2 ({size2}) < size1 ({size1})")
    if size1 == size2:
        if bytearray_proof:
            raise ValueError("size1=size2, but bytearray_proof is not empty")
        verify_match(root1, root2)
        return
    if size1 == 0:
        if bytearray_proof:
            raise ValueError(
                f"expected empty bytearray_proof, but got {len(bytearray_proof)} components"
            )
        return
    if not bytearray_proof:
        raise ValueError("empty bytearray_proof")

    inner, border = decomp_incl_proof(size1 - 1, size2)
    shift = (size1 & -size1).bit_length() - 1
    inner -= shift

    seed, start = (root1, 0) if size1 == 1 << shift else (bytearray_proof[0], 1)

    if len(bytearray_proof) != start + inner + border:
        raise ValueError(
            f"wrong bytearray_proof size {len(bytearray_proof)}, want {start + inner + border}"
        )

    bytearray_proof = bytearray_proof[start:]

    mask = (size1 - 1) >> shift
    hash1 = chain_inner_right(hasher, seed, bytearray_proof[:inner], mask)
    hash1 = chain_border_right(hasher, hash1, bytearray_proof[inner:])
    verify_match(hash1, root1)

    hash2 = chain_inner(hasher, seed, bytearray_proof[:inner], mask)
    hash2 = chain_border_right(hasher, hash2, bytearray_proof[inner:])
    try:
        verify_match(hash2, root2)
        print("Consistency verification successful")
    except Exception:
        print("Consistency verification failed")
        exit()


def verify_match(calculated, expected):
    """Verifies that the calculated hash matches the expected hash."""
    if calculated != expected:
        raise RootMismatchError(expected, calculated)


def decomp_incl_proof(index, size):
    """Decomposes the inclusion proof to get inner and border sizes."""
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count("1")
    return inner, border


def inner_proof_size(index, size):
    """Calculates the inner proof size based on index and size."""
    return (index ^ (size - 1)).bit_length()


def chain_inner(hasher, seed, proof, index):
    """Chains hashes for inner nodes based on the proof and index."""
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, h)
        else:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_inner_right(hasher, seed, proof, index):
    """Chains hashes from the right for inner nodes based on proof and index."""
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_border_right(hasher, seed, proof):
    """Chains hashes for border nodes based on the proof."""
    for h in proof:
        seed = hasher.hash_children(h, seed)
    return seed


class RootMismatchError(Exception):
    """Custom exception raised when root hashes do not match."""

    def __init__(self, expected_root, calculated_root):
        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))

    def __str__(self):
        return f"calculated root:\n{self.calculated_root}\n does not match expected root:\n{self.expected_root}"


def root_from_inclusion_proof(hasher, index, size, leaf_hash, proof):
    """Calculates the root from an inclusion proof."""
    if index >= size:
        raise ValueError(f"index is beyond size: {index} >= {size}")

    if len(leaf_hash) != hasher.size():
        raise ValueError(
            f"leaf_hash has unexpected size {len(leaf_hash)}, want {hasher.size()}"
        )

    inner, border = decomp_incl_proof(index, size)
    if len(proof) != inner + border:
        raise ValueError(f"wrong proof size {len(proof)}, want {inner + border}")

    res = chain_inner(hasher, leaf_hash, proof[:inner], index)
    res = chain_border_right(hasher, res, proof[inner:])
    return res


def verify_inclusion(hasher, index, size, leaf_hash, proof, root, debug=False):
    """Verifies the inclusion of a leaf hash in a Merkle tree."""
    bytearray_proof = [bytes.fromhex(elem) for elem in proof]
    bytearray_root = bytes.fromhex(root)
    bytearray_leaf = bytes.fromhex(leaf_hash)
    calc_root = root_from_inclusion_proof(
        hasher, index, size, bytearray_leaf, bytearray_proof
    )
    if debug:
        print("Calculated root hash", calc_root.hex())
        print("Given root hash", bytearray_root.hex())

    try:
        verify_match(calc_root, bytearray_root)
        print("Offline root hash calculation for inclusion verified")
    except Exception as e:
        if debug:
            print("Exception:", e)
        print("Offline root hash calculation for inclusion could not be verified")
        exit()


# Requires entry["body"] output for a log entry
# Returns the leaf hash according to the RFC 6962 spec
def compute_leaf_hash(body):
    """Computes the leaf hash from the entry body."""
    entry_bytes = base64.b64decode(body)
    h = hashlib.sha256()
    h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
    h.update(entry_bytes)
    return h.hexdigest()
