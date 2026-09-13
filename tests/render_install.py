#!/usr/bin/env python3
"""Render an isolated test installation with the locally built image."""
import re
import sys
from pathlib import Path

manifest = Path('deploy/tlb.yaml').read_text()
manifest, count = re.subn(r'ghcr\.io/niklasrosenstein/tlb:\d+\.\d+\.\d+', sys.argv[1], manifest)
assert count == 1
manifest = manifest.replace('imagePullPolicy: IfNotPresent', 'imagePullPolicy: Never')
manifest = manifest.replace('replicas: 1', 'replicas: ' + sys.argv[2])
print(manifest)
