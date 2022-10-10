# PyTiled Parser

PyTiled Parser is a Python Library for parsing JSON formatted
[Tiled Map Editor](https://www.mapeditor.org/) maps and tilesets to be used as maps and levels for 2D top-down (orthogonal, hexogonal, or isometric) or side-scrolling games in a strictly typed fashion.

PyTiled Parser is not tied to any particular graphics library, and can be used
with [Arcade](http://arcade.academy), 
[Pyglet](https://pyglet.readthedocs.io/en/pyglet-1.3-maintenance/), 
[Pygame](https://www.pygame.org/news), etc. 

* Documentation available at: https://pytiled-parser.readthedocs.io/
* GitHub project at: https://github.com/Beefy-Swain/pytiled_parser
* PiPy: https://pypi.org/project/pytiled-parser/

The [Arcade](http://arcade.academy) library has 
[supporting code](http://arcade.academy/arcade.html#module-arcade.tilemap) to 
integrate PyTiled with that 2D libary, and 
[example code](http://arcade.academy/examples/index.html#tmx-files-tiled-map-editor) showing its use.

Original module by [Beefy-Swain](https://github.com/Beefy-Swain). 
Significant contributions from [pvcraven](https://github.com/pvcraven) and [Cleptomania](https://github.com/Cleptomania).

## Development
To develop pytiled parser, clone the repo, create a `venv` using a supported Python version, and activate it. Then install the package as well as all testing dependencies with the command `python -m pip install -e ".[tests]"`.

### Testing
Run `pytest --cov=pytiled_parser` to run the test harness and report coverage.