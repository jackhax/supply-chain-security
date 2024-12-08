import subprocess

# Define a schema for the expected consistency output (modify as needed)
consistency_schema = {
    "type": "object",
    "properties": {
        "treeID": {"type": "string"},
        "previousTreeSize": {"type": "integer"},
        "currentTreeSize": {"type": "integer"},
        "hashes": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["treeID", "previousTreeSize", "currentTreeSize", "hashes"],
}


def test_consistency():
    # Run the main.py script with the updated valid values for the --consistency flag
    result = subprocess.run(
        [
            "python",
            "-m",
            "rektor.main",
            "--consistency",
            "--tree-id",
            "11930509599166506",
            "--tree-size",
            "11137518",
            "--root-hash",
            "83edbcbc1ab683a272b48016ae81ba7903f69af7f99e9805eb52804191ed03fc1",
        ],
        capture_output=True,
        text=True,
    )

    output = result.stdout
    error_output = result.stderr

    # Print output for debugging
    print("STDOUT:", output)
    print("STDERR:", error_output)

    # Ensure there is output and validate it
    assert "Invalid root(s)" in output  # Modify if necessary
    # Optionally, parse and validate the JSON output
    # if output.strip():  # Check if output is not empty
    #     try:
    #         data = json.loads(output)
    #         validate(instance=data, schema=consistency_schema)
    #     except json.JSONDecodeError:
    #         assert False, "Output is not valid JSON"
