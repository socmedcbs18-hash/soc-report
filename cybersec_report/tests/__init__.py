"""Test memakai folder data sementara agar tidak menyentuh database/ asli."""
import os
import tempfile

os.environ.setdefault("CYBERSEC_DATA_DIR", tempfile.mkdtemp(prefix="cybersec_test_"))
