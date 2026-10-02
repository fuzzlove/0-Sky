"""Portable CLI for canonical environment detection, intake and installed audit."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
from .engine import Engine
from .orchestrator import CompatibilityEngine
from .environment import detect, load
from .inventory import audit_installed
from .integration import registry_view


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--environment', type=Path)
    sub = parser.add_subparsers(dest='operation', required=True)
    sub.add_parser('detect')
    scan = sub.add_parser('analyze')
    scan.add_argument('source', type=Path)
    scan.add_argument('--adapter', action='append', default=[], choices=['rootless-v1'])
    batch = sub.add_parser('analyze-batch')
    batch.add_argument('sources', type=Path, nargs='+')
    batch.add_argument('--workers', type=int, default=4)
    sub.add_parser('audit')
    sub.add_parser('registry')
    args = parser.parse_args()
    if args.operation == 'registry':
        value = registry_view(args.state)
    else:
        env = load(args.environment) if args.environment else detect()
        if args.operation == 'detect':
            value = asdict(env)
        elif args.operation == 'audit':
            value = audit_installed(env, args.state)
        elif args.operation == 'analyze-batch':
            results = CompatibilityEngine(args.state, env).analyze_batch(
                args.sources, args.workers)
            value = {'schema_version': 2,
                     'components': [item.report.to_dict() for item in results]}
        else:
            report, _, _ = Engine(args.state, env).evaluate(args.source, args.adapter)
            value = report.to_dict()
    print(json.dumps(value, sort_keys=True, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
