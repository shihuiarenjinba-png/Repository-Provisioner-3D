"""Stable CLI entrypoint for the Package + Identity Provisioner."""
from package_identity_provisioner import *  # noqa: F401,F403
from package_identity_provisioner import main

if __name__ == "__main__":
    raise SystemExit(main())
