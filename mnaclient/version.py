_version = None
_version_long = None
def _make_version():
    global _version, _version_long
    if _version is None or _version_long is None:
        import subprocess
        rv = subprocess.run(('/usr/bin/env', 'git', 'describe', '--tags', '--abbrev=0'), stdout=subprocess.PIPE)
        _version = rv.stdout.decode().strip()
        rv = subprocess.run(('/usr/bin/env', 'git', 'describe', '--tags', '--long'), stdout=subprocess.PIPE)
        _version_long = rv.stdout.decode().strip()
    return _version, _version_long

__version__ = _make_version()[0]

