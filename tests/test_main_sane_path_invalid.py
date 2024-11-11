import pytest
from main import sane_path
from pathlib import Path

def test_sane_path_invalid():
    # Verify that sane_path raises FileNotFoundError for an invalid path
    with pytest.raises(FileNotFoundError):
        sane_path("/non/existent/file.txt")