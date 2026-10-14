#!/usr/bin/env python3
"""Prepare three copies using the fixed S3 example's own encode/ref/seal helpers."""
from pathlib import Path
import shutil

import contract as c


def main():
    root = Path.cwd()
    if c.ROOT != root / 'source':
        raise ValueError('contract did not load from the fixed export')
    original = root / 'source/reference/s3-observation-example/inputs/seaweedfs-4.48/instance/bundles/supported'
    c.Bundle(original)
    for name in ('matching', 'target-mismatch', 'missing-post'):
        folder = root / 'cases' / name
        shutil.copytree(original, folder)
        if name == 'matching':
            continue  # Including the original manifest, every byte is unchanged.
        (folder / 'manifest.json').unlink()
        if name == 'target-mismatch':
            request = c.decode((folder / 'get-request.json').read_bytes())
            request['key'] = 'other.txt'
            (folder / 'get-request.json').write_bytes(c.encode(request))
            transport = c.decode((folder / 'get-transport.json').read_bytes())
            transport['request_ref'] = c.descriptor('get-request.json', (folder / 'get-request.json').read_bytes())
            (folder / 'get-transport.json').write_bytes(c.encode(transport))
        else:
            (folder / 'post.json').unlink()
        c.seal(folder)
        c.Bundle(folder)
    print('Prepared matching, target-mismatch and missing-post copies; no native S3 request was made.')


if __name__ == '__main__':
    main()
