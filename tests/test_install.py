"""Pure-logic checks for the cross-platform installer/launcher. No network, no subprocesses."""

import argparse
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from install import python_ok, venv_python
from start import port_arg


@pytest.mark.parametrize(
    "version,expected",
    [((3, 11, 9), False), ((3, 12, 0), True), ((3, 13, 1), True), ((2, 7, 18), False)],
)
def test_python_ok(version, expected):
    assert python_ok(version) is expected


def test_venv_python_posix():
    p = venv_python(Path("/opt/PromptSiege"), windows=False)
    assert PurePosixPath(p).as_posix().endswith("PromptSiege/venv/bin/python")


def test_venv_python_windows():
    p = venv_python(Path(r"C:\src\PromptSiege"), windows=True)
    assert PureWindowsPath(p).name == "python.exe"
    assert PureWindowsPath(p).parent.name == "Scripts"


@pytest.mark.parametrize("value", ["1", "8000", "65535"])
def test_port_arg_valid(value):
    assert port_arg(value) == int(value)


@pytest.mark.parametrize("value", ["0", "65536", "-1", "abc", ""])
def test_port_arg_invalid(value):
    with pytest.raises(argparse.ArgumentTypeError):
        port_arg(value)
