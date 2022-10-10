import pytest

from pytiled_parser.util import parse_color


def test_parse_color_wrong_format():
    with pytest.raises(ValueError):
        color = parse_color("#ff0000ff0")


def test_parse_color_no_hash():
    color = parse_color("ff0000")
    assert color == (255, 0, 0, 255)


def test_parse_color_no_alpha():
    color = parse_color("#ff0000")
    assert color == (255, 0, 0, 255)
