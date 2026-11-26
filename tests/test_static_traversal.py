import importlib
import pytest

MODS = ["agent_capsule_jail.server", ]


@pytest.mark.parametrize("mod", MODS)
@pytest.mark.parametrize("raw,expected", [
    ("/", ""), ("/index.html", "index.html"), ("/assets/app.js", "assets/app.js"),
    ("/../../etc/passwd", None), ("/static/../../../etc/passwd", None),
    ("/%2e%2e/%2e%2e/etc/passwd", None), ("/..%2f..%2fetc/passwd", None),
    ("/a\\..\\..\\x", None), ("/C:/Windows/win.ini", None),
])
def test_safe_rel(mod, raw, expected):
    assert importlib.import_module(mod)._safe_rel(raw) == expected
