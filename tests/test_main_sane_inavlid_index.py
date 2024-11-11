from main import sane_index

def test_sane_index():
    result = sane_index('aa1234')
    assert not result
