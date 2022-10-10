import os
from pathlib import Path

import pytest

from pytiled_parser import parse_map


def test_cross_template_tmx_json():
    with pytest.raises(NotImplementedError):
        parse_map(Path(os.path.dirname(os.path.abspath(__file__))) / "map.tmx")


def test_cross_template_json_tmx():
    with pytest.raises(NotImplementedError):
        parse_map(Path(os.path.dirname(os.path.abspath(__file__))) / "map.json")
