"""Test memakai folder data sementara agar tidak menyentuh database/ asli."""
import os
import tempfile

os.environ.setdefault("SOC_INCIDENT_DATA_DIR", tempfile.mkdtemp(prefix="soc_incident_test_"))
