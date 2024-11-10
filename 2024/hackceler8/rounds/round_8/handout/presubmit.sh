#!/usr/bin/env bash

for f in $(git diff main --name-only | grep ".py"); do
  if [ -e $f ]; then
    # Public one
    #autopep8 -i -r --max-line-length 80 --indent-size=2 $f
    # Google internal one
    pyformat -i -r $f
    PYTHONPATH=. pylint --rcfile pylintrc $f
  fi
done
