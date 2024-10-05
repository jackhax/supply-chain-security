import argparse
from util import extract_public_key, verify_artifact_signature
from merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
)
import json, base64, requests
from pathlib import Path
import configparser  # For reading the config file

# Initialize the global base_url from config
config = configparser.ConfigParser()
config.read("config.ini")
base_url = config["API"]["base_url"]


# Check if the provided index is a valid number
def sane_index(index):
    """
    Check if the provided log index is a valid number.

    Args:
        index (str or int): The log index to validate.

    Returns:
        bool: True if the index is a valid number, False otherwise.
    """
    return str(index).isdigit()


# Check if the provided path is a valid file path and exists
def sane_path(path):
    """
    Validate that the provided file path exists.

    Args:
        path (str): The file path to validate.

    Raises:
        FileNotFoundError: If the file path does not exist.
    """
    Path(path).resolve(strict=True)


# Fetches and decodes the body of a log entry by its index
def get_log_body(log_index, debug=False):
    """
    Fetch and decode the body of a Rekor log entry by its index.

    Args:
        log_index (int): The log index to fetch.
        debug (bool, optional): Flag to enable debug output. Defaults to False.

    Returns:
        dict: The decoded body of the log entry.

    Raises:
        AssertionError: If the log index is not a valid number.
    """
    assert sane_index(log_index), "The value is Not a Number (NaN)."
    api = f"{base_url}/log/entries?logIndex={log_index}"
    data = requests.get(api).json()
    body = next(iter(data.values()))["body"]
    body = json.loads(base64.b64decode(body))
    return body


# Fetches a full log entry by its index
def get_log_entry(log_index, debug=False):
    """
    Fetch a full Rekor log entry by its index.

    Args:
        log_index (int): The log index to fetch.
        debug (bool, optional): Flag to enable debug output. Defaults to False.

    Returns:
        dict: The full log entry as returned by the Rekor server.
    """
    assert sane_index(log_index), "The value is Not a Number (NaN)."
    api = f"{base_url}/log/entries?logIndex={log_index}"
    data = requests.get(api).json()
    log = next(iter(data.values()))
    return log


# Fetches the verification proof (inclusion proof) for a log entry
def get_verification_proof(log_index, debug=False):
    """
    Fetch the verification proof (inclusion proof) for a given log entry.

    Args:
        log_index (int): The log index to fetch proof for.
        debug (bool, optional): Flag to enable debug output. Defaults to False.

    Returns:
        dict: The inclusion proof containing the leaf hash and other proof data.
    """
    assert sane_index(log_index), "The value is Not a Number (NaN)."
    log = get_log_entry(log_index)
    body = log["body"]
    leaf_hash = compute_leaf_hash(body)
    proof = log["verification"]["inclusionProof"]
    proof["leafHash"] = leaf_hash
    return proof


# Verifies the inclusion of an artifact in the transparency log
def inclusion(log_index, artifact_filepath, debug=False):
    """
    Verify the inclusion of an artifact in the transparency log by its log index.
    """
    sane_path(artifact_filepath)
    log = get_log_body(log_index)
    signature = base64.b64decode(log["spec"]["signature"]["content"])
    cert = base64.b64decode(log["spec"]["signature"]["publicKey"]["content"])
    public_key = extract_public_key(cert)
    verify_artifact_signature(signature, public_key, artifact_filepath)
    proof = get_verification_proof(log_index)
    verify_inclusion(
        DefaultHasher,
        proof["logIndex"],
        proof["treeSize"],
        proof["leafHash"],
        proof["hashes"],
        proof["rootHash"],
    )


# Fetches the latest checkpoint from the Rekor log server
def get_latest_checkpoint(debug=False):
    """
    Fetch the latest checkpoint from the Rekor log server.
    """
    api = f"{base_url}/log"
    checkpoint = requests.get(api).json()
    return checkpoint


# Verifies the consistency of a checkpoint with the latest checkpoint from the log
def consistency(prev_checkpoint, debug=False):
    """
    Verify the consistency between a previous checkpoint and the latest one using Merkle proof.
    """
    assert prev_checkpoint != {}, "Previous checkpoint empty"
    checkpoint = get_latest_checkpoint()

    rootHash = checkpoint["rootHash"]
    treeSize = checkpoint["treeSize"]
    proof = requests.get(
        f'{base_url}/log/proof?firstSize={prev_checkpoint["treeSize"]}&lastSize={treeSize}'
    ).json()["hashes"]

    verify_consistency(
        DefaultHasher,
        prev_checkpoint["treeSize"],
        treeSize,
        proof,
        prev_checkpoint["rootHash"],
        rootHash,
    )


# Entry point for the command-line interface
def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")

    parser.add_argument(
        "-d", "--debug", help="Debug mode", required=False, action="store_true"
    )
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an entry in the Rekor Transparency Log using log index",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact", help="Artifact filepath for verifying signature", required=False
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )

    args = parser.parse_args()

    if args.debug:
        debug = True
        print("enabled debug mode")

    if args.checkpoint:
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))

    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)

    if args.consistency:
        if not args.tree_id or not args.tree_size or not args.root_hash:
            print(
                "Please specify tree id, tree size, and root hash for prev checkpoint"
            )
            return

        prev_checkpoint = {
            "treeID": args.tree_id,
            "treeSize": args.tree_size,
            "rootHash": args.root_hash,
        }

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()
