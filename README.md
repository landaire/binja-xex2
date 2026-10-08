# Xbox 360 XEX2 loader for Binary Ninja

Loads Xbox 360 XEX2 executables and PowerPC PE images.

## Install with uv

Clone this repository into Binary Ninja's user plugins directory (or symlink
an existing checkout there). On Linux:

```sh
git clone git@github.com:landaire/binja-xex2.git ~/.binaryninja/plugins/binja-xex2
cd ~/.binaryninja/plugins/binja-xex2
uv sync --python 3.13
```

Select the Python minor version used by Binary Ninja's Python console
(`import sys; print(sys.version)`). Binary Ninja 6.0 on Linux bundles Python
3.13; installations using Python 3.10 should use `uv sync --python 3.10`.
The `xex2` native extension must match Binary Ninja's Python minor version.
The loader automatically adds this checkout's `.venv` site-packages to its
import path. Restart Binary Ninja after installation.

The loader supports the legacy writable BinaryView handle and Binary Ninja 6's
read-only handle property. It reuses the Xbox 360 convention and architecture
hook when the kernel/hypervisor loader package is already loaded. Compatibility tests run without a Binary Ninja license:

```sh
uv run python -m unittest discover -s tests -v
```
