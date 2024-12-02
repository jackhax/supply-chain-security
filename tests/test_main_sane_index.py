from rektor.main import sane_index

def test_sane_index():
    result = sane_index(1234)
    result = result and sane_index('1234')
    assert result
