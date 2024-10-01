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


# Check if the provided index is a valid number
def sane_index(index):
    return str(index).isdigit()  # Returns True if the index is a digit (a valid number)


# Check if the provided path is a valid file path and exists
def sane_path(path):
    Path(path).resolve(
        strict=True
    )  # Resolves the path and checks if it exists (raises an error if not)
    # This can be extended to restrict paths to a specific base directory for better security (LFI prevention).


# Fetches and decodes the body of a log entry by its index
def get_log_body(log_index, debug=False):
    assert sane_index(
        log_index
    ), "The value is Not a Number (NaN)."  # Validate that the log index is a number
    api = f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}"
    data = requests.get(api).json()  # Make an API call to fetch log data
    body = next(iter(data.values()))[
        "body"
    ]  # Extract the 'body' field from the log entry
    body = json.loads(base64.b64decode(body))  # Decode the body from base64
    return body


# Fetches a full log entry by its index
def get_log_entry(log_index, debug=False):
    assert sane_index(
        log_index
    ), "The value is Not a Number (NaN)."  # Validate log index
    api = f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}"
    data = requests.get(api).json()  # Fetch log entry from the API
    log = next(iter(data.values()))  # Get the first log entry
    return log


# Fetches the verification proof (inclusion proof) for a log entry
def get_verification_proof(log_index, debug=False):
    assert sane_index(
        log_index
    ), "The value is Not a Number (NaN)."  # Validate log index
    log = get_log_entry(log_index)  # Fetch the log entry
    body = log["body"]
    leaf_hash = compute_leaf_hash(body)  # Compute the leaf hash for the log entry
    proof = log["verification"]["inclusionProof"]  # Extract the inclusion proof
    proof["leafHash"] = leaf_hash  # Add the computed leaf hash to the proof
    return proof


# Verifies the inclusion of an artifact in the transparency log
def inclusion(log_index, artifact_filepath, debug=False):
    sane_path(artifact_filepath)  # Ensure that the artifact file exists
    log = get_log_body(log_index)  # Fetch the log body
    signature = base64.b64decode(
        log["spec"]["signature"]["content"]
    )  # Decode the signature from base64
    cert = base64.b64decode(
        log["spec"]["signature"]["publicKey"]["content"]
    )  # Decode the public key
    public_key = extract_public_key(cert)  # Extract the public key from the certificate
    verify_artifact_signature(
        signature, public_key, artifact_filepath
    )  # Verify the artifact signature
    proof = get_verification_proof(log_index)  # Get the inclusion proof
    # Verify that the log entry is included in the transparency log
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
    api = "https://rekor.sigstore.dev/api/v1/log"  # API to fetch the latest checkpoint
    checkpoint = requests.get(api).json()  # Make API call to fetch checkpoint
    return checkpoint


# Verifies the consistency of a checkpoint with the latest checkpoint from the log
def consistency(prev_checkpoint, debug=False):
    assert (
        prev_checkpoint != {}
    ), "Previous checkpoint empty"  # Ensure the previous checkpoint is not empty
    checkpoint = get_latest_checkpoint()  # Fetch the latest checkpoint

    treeID = checkpoint["treeID"]
    rootHash = checkpoint["rootHash"]
    treeSize = checkpoint["treeSize"]
    # Fetch the proof of consistency between the previous checkpoint and the current one
    proof = requests.get(
        f'https://rekor.sigstore.dev/api/v1/log/proof?firstSize={prev_checkpoint["treeSize"]}&lastSize={treeSize}'
    ).json()["hashes"]

    # Verify the consistency between the previous and the latest checkpoint using the Merkle proof
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
    # Initialize argument parser for handling command-line arguments
    parser = argparse.ArgumentParser(description="Rekor Verifier")

    # Argument for enabling debug mode
    parser.add_argument(
        "-d", "--debug", help="Debug mode", required=False, action="store_true"
    )  # Default false

    # Argument for fetching the latest checkpoint
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint\
                        from Rekor Server public instance",
        required=False,
        action="store_true",
    )

    # Argument for verifying inclusion of an entry in the Rekor log
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567",
        required=False,
        type=int,
    )

    # Argument for specifying artifact file path
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying\
                        signature",
        required=False,
    )

    # Argument for verifying consistency between checkpoints
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given\
                        checkpoint with the latest checkpoint.",
        action="store_true",
    )

    # Arguments for checkpoint consistency verification
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )

    # Parse arguments
    args = parser.parse_args()

    if args.debug:
        debug = True  # Enable debug mode
        print("enabled debug mode")

    # Fetch and print the latest checkpoint if requested
    if args.checkpoint:
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))

    # Verify inclusion in the Rekor log if requested
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)

    # Verify consistency of the previous checkpoint with the latest one
    if args.consistency:
        # Ensure necessary parameters for the previous checkpoint are provided
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        # Construct the previous checkpoint object
        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        # Perform the consistency check
        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()
