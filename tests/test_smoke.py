"""Minimal tests so CI collects at least one item and coverage can run."""


def test_package_imports() -> None:
    import blackbox_recon  # noqa: F401
