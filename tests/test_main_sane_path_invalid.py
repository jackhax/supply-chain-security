import pytest
from rektor.main import sane_path


def test_sane_path_invalid():
    # Verify that sane_path raises FileNotFoundError for an invalid path
    with pytest.raises(FileNotFoundError):
        sane_path("/non/existent/file.txt")
