"""Binary Ninja plugin entry point for the Xbox 360 XEX2 / PE loader.

Binary Ninja imports this package when the repository directory is placed
(or symlinked) in the user plugins folder. Importing the loader module
registers the BinaryViews, the PPC64 architecture hook, and the Xbox 360
platform as an import side effect.
"""

from . import xbox360_xex2_loader  # noqa: F401  (registration happens on import)
