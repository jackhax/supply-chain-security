"""
Rekor Transparency Log Verifier

This module interacts with the Rekor transparency log to:
- Verify artifact inclusion using a log index.
- Fetch log entries and checkpoints.
- Verify consistency between two checkpoints with Merkle proofs.

Requires a `config.ini` file containing the Rekor API base URL.

Usage:
    - Enable debug mode: 
        python verifier.py --debug
    - Fetch the latest checkpoint:
        python verifier.py --checkpoint
    - Verify artifact inclusion in the Rekor log using log index:
        python verifier.py --inclusion <log_index> --artifact <filepath>
    - Verify consistency between a previous checkpoint and the latest:
        python verifier.py --consistency --tree-id <tree_id> 
        --tree-size <tree_size> --root-hash <root_hash>

Dependencies:
    - argparse, requests, json, base64, configparser
    - util, merkle_proof (custom modules)
"""

import argparse
import json
import base64
from pathlib import Path
import requests
from .util import (
    extract_public_key,
    verify_artifact_signature,
)  # Utility functions for signature handling
from .merkle_proof import (  # Importing Merkle proof-related functions for verifying proofs
    DefaultHasher,
    RootMismatchError,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
)

# Initialize the global base_url 
base_url = 'https://rekor.sigstore.dev/api/v1'


# Check if the provided index is a valid number
def sane_index(index):
    """
    Check if the provided log index is a valid number.
    input: int:index
    output: bool
    """
    return str(index).isdigit()  # Validate if the index is a digit (i.e., a number)


# Check if the provided path is a valid file path and exists
def sane_path(path):
    """
    Validate that the provided file path exists.
    """
    Path(path).resolve(strict=True)  # Ensure the path is valid and the file exists


# Fetches and decodes the body of a log entry by its index
def get_log_body(log_index, debug=False):
    """
    Fetch and decode the body of a Rekor log entry by its index.
    """
    if not sane_index(log_index):  # Check if log index is valid
        if debug:
            print("The value is Not a Number (NaN).")  # Print a message in debug mode
        return None

    api = f"{base_url}/log/entries?logIndex={log_index}"  # Construct API endpoint URL
    try:
        data = requests.get(
            api, timeout=10
        ).json()  # Send GET request to fetch log entry
    except requests.exceptions.Timeout:  # Handle request timeout
        if debug:
            print("Timed out")  # Print timeout message in debug mode
        return None

    body = next(iter(data.values()))["body"]  # Extract the body from the log entry
    body = json.loads(
        base64.b64decode(body)
    )  # Decode the base64-encoded body and parse JSON
    return body  # Return the decoded log body


# Fetches a full log entry by its index
def get_log_entry(log_index, debug=False):
    """
    Fetch a full Rekor log entry by its index.
    """
    if not sane_index(log_index):  # Check if the log index is valid
        if debug:
            print("The value is Not a Number (NaN).")
        return None

    api = f"{base_url}/log/entries?logIndex={log_index}"  # Construct the API URL

    try:
        data = requests.get(api, timeout=10).json()  # Fetch the log entry
    except requests.exceptions.Timeout:  # Handle timeout errors
        if debug:
            print("Timed out")
        return None

    log = next(iter(data.values()))  # Extract the log entry from the returned data
    return log  # Return the full log entry


# Fetches the verification proof (inclusion proof) for a log entry
def get_verification_proof(log_index, debug=False):
    """
    Fetch the verification proof (inclusion proof) for a given log entry.
    """
    if not sane_index(log_index):  # Validate the log index
        if debug:
            print("The value is Not a Number (NaN).")
        return None

    log = get_log_entry(log_index)  # Fetch the full log entry
    body = log["body"]  # Extract the body from the log entry
    leaf_hash = compute_leaf_hash(body)  # Compute the leaf hash for inclusion proof
    proof = log["verification"][
        "inclusionProof"
    ]  # Extract the inclusion proof from the log
    proof["leafHash"] = leaf_hash  # Add the computed leaf hash to the proof
    return proof  # Return the inclusion proof


# Verifies the inclusion of an artifact in the transparency log
def inclusion(log_index, artifact_filepath, debug=False):
    """
    Verify the inclusion of an artifact in the transparency log by its log index.
    """
    sane_path(artifact_filepath)  # Validate the file path
    log = get_log_body(log_index)  # Fetch the log body
    try:
        signature = base64.b64decode(
            log["spec"]["signature"]["content"]
        )  # Decode the signature
    except KeyError:
        print('Invalid log index')
        return

    cert = base64.b64decode(
        log["spec"]["signature"]["publicKey"]["content"]
    )  # Decode the public key
    public_key = extract_public_key(cert)  # Extract the public key from the certificate
    verify_artifact_signature(
        signature, public_key, artifact_filepath
    )  # Verify the signature
    proof = get_verification_proof(log_index)  # Fetch the inclusion proof
    verify_inclusion(  # Verify the inclusion proof
        DefaultHasher,
        proof["logIndex"],
        proof["treeSize"],
        proof["leafHash"],
        proof["hashes"],
        proof["rootHash"],
    )
    if debug:
        print("inclusion successful")  # Print success message in debug mode


# Fetches the latest checkpoint from the Rekor log server
def get_latest_checkpoint(debug=False):
    """
    Fetch the latest checkpoint from the Rekor log server.
    """
    api = f"{base_url}/log"  # Construct the API URL to fetch the latest checkpoint

    try:
        checkpoint = requests.get(
            api, timeout=10
        ).json()  # Send GET request to fetch checkpoint
    except requests.exceptions.Timeout:  # Handle timeout error
        if debug:
            print("Timed out")  # Print timeout message in debug mode
        return None

    return checkpoint  # Return the fetched checkpoint


# Verifies the consistency of a checkpoint with the latest checkpoint from the log
def consistency(prev_checkpoint, debug=False):
    """
    Verify the consistency between a previous checkpoint and the latest one using Merkle proof.
    """
    if prev_checkpoint == {}:  # Check if the previous checkpoint is empty
        if debug:
            print(
                "Previous checkpoint empty"
            )  # Print message if the checkpoint is empty
        return None

    checkpoint = get_latest_checkpoint()  # Fetch the latest checkpoint

    root_hash = checkpoint[
        "rootHash"
    ]  # Extract the root hash from the latest checkpoint
    tree_size = checkpoint["treeSize"]  # Extract the tree size

    try:
        proof = requests.get(  # Send GET request to fetch the consistency proof
            f'{base_url}/log/proof?firstSize={prev_checkpoint["treeSize"]}&lastSize={tree_size}',
            timeout=10,
        ).json()[
            "hashes"
        ]  # Extract the list of hashes from the response
        print(proof)
    except requests.exceptions.Timeout:  # Handle timeout error
        print("Timed out")
        return None

    verify_consistency(  # Verify the consistency proof
        DefaultHasher,
        prev_checkpoint["treeSize"],
        tree_size,
        proof,
        prev_checkpoint["rootHash"],
        root_hash,
    )

    return True  # Return True on successful consistency verification


# Entry point for the command-line interface
def main():
    """
    Entry point for the command-line interface
    """
    debug = False  # Initialize debug mode as False by default
    parser = argparse.ArgumentParser(
        description="Rekor Verifier"
    )  # Create argument parser

    # Add arguments to the parser
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

    args = parser.parse_args()  # Parse the command-line arguments

    if args.debug:  # Check if debug mode is enabled
        debug = True
        print("enabled debug mode")  # Print debug mode enabled message

    if args.checkpoint:  # If checkpoint flag is set, fetch the latest checkpoint
        checkpoint = get_latest_checkpoint(debug)
        print(
            json.dumps(checkpoint, indent=4)
        )  # Print the checkpoint in formatted JSON

    if args.inclusion:  # If inclusion flag is set, verify inclusion of the log entry
        inclusion(args.inclusion, args.artifact, debug)

    if (
        args.consistency
    ):  # If consistency flag is set, verify the consistency of checkpoints
        if (
            not args.tree_id or not args.tree_size or not args.root_hash
        ):  # Ensure required fields are provided
            print(
                "Please specify tree id, tree size, and root hash for prev checkpoint"
            )
            return

        prev_checkpoint = {  # Build the previous checkpoint object
            "treeID": args.tree_id,
            "treeSize": args.tree_size,
            "rootHash": args.root_hash,
        }

        try:
            consistency(prev_checkpoint, debug)  # Perform consistency verification
        except RootMismatchError:
            print('Consistency cannot be verified')


if __name__ == "__main__":
    main()  # Run the main function when script is executed
