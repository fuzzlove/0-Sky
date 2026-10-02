#!/usr/bin/env python3
"""Legacy kit entry-point guard. All compatibility decisions use the shared engine."""
import argparse
from pathlib import Path
import sys

for ancestor in Path(__file__).resolve().parents:
    for runtime in (ancestor / 'bridge/DeviceRuntime',
                    ancestor / 'automation/CrypStoreAutomation',
                    ancestor / 'automation/tools/srd-runtime-manager'):
        if (runtime / 'zero_sky_compat').is_dir():
            sys.path.insert(0, str(runtime))
            break


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation')
    args = parser.parse_args()
    try:
        from zero_sky_compat.integration import CompatibilityBlocked, block_legacy_mutation
    except ImportError:
        parser.exit(193, 'Compatibility engine unavailable; installation is blocked.\n')
    try:
        block_legacy_mutation(args.operation)
    except CompatibilityBlocked as error:
        parser.exit(193, str(error) + '\n')


if __name__ == '__main__':
    main()
