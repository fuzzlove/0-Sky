"""Generate deterministic adaptation plans from analyzed evidence."""
from __future__ import annotations

from .rules import RULES


RISK = {
    'rootless-v1': 'LOW',
    'dependency-provider': 'MEDIUM',
    'reviewed-service-backend': 'HIGH',
    'apple-authorized-research-signing': 'HIGH',
}


def plan(report):
    problems = []
    adaptations = []
    seen = set()
    for issue in sorted(report.issues,
                        key=lambda value: (value['code'], value['path'], value['detail'])):
        problems.append({'code': issue['code'], 'path': issue['path'],
                         'detail': issue['detail'], 'severity': issue['severity']})
        rule = RULES.get(issue['code'])
        if not rule or not rule.get('adapter'):
            continue
        adapter = rule['adapter']
        if adapter in seen:
            continue
        seen.add(adapter)
        adaptations.append({'adapter': adapter,
                            'requires': sorted(rule.get('requires', [])),
                            'risk': RISK.get(adapter, 'MEDIUM')})
    risks = [item['risk'] for item in adaptations]
    risk = 'HIGH' if 'HIGH' in risks else 'MEDIUM' if 'MEDIUM' in risks else 'LOW'
    return {
        'schema_version': 1,
        'package': report.component,
        'version': report.version,
        'source_hash': report.source_hash,
        'environment_hash': report.environment_hash,
        'detected_problems': problems,
        'adaptations': adaptations,
        'risk': risk,
        'expected_state': ('COMPATIBLE_WITH_ADAPTER' if adaptations else
                           report.compatibility_state),
    }
