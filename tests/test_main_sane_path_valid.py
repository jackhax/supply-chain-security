import pytest
from rektor.main import sane_path


def test_sane_path_valid(tmp_path):
    # Create a temporary file in the tmp_path directory
    test_file = tmp_path / "test_file.txt"
    test_file.write_text("This is a test file.")  # Write some content to the file

    # Verify that sane_path does not raise an exception for the valid path
    try:
        sane_path(str(test_file))
    except FileNotFoundError:
        pytest.fail("sane_path raised FileNotFoundError for a valid path")
