#!/usr/bin/env python3
"""Offline validation of AGP documentation contracts, not a runtime/security scan."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import posixpath
import re
import sys
from urllib.parse import unquote, urlsplit

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from openapi_spec_validator import validate
from openapi_spec_validator.readers import read_from_filename
from pglast import parse_sql

ROOT = Path(__file__).resolve().parent
CHECKER = FormatChecker()


@CHECKER.checks('agp-uint63')
def uint63(value):
    return isinstance(value, str) and bool(re.fullmatch(r'0|[1-9][0-9]{0,18}', value)) and int(value) <= 9223372036854775807


@CHECKER.checks('agp-cidr', raises=(ValueError, TypeError))
def cidr(value):
    return isinstance(value, str) and str(ipaddress.ip_network(value, strict=True)) == value


@CHECKER.checks('agp-hostname')
def hostname(value):
    if not isinstance(value, str) or len(value) > 253 or value.endswith('.'):
        return False
    return all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in value.split('.'))


@CHECKER.checks('agp-upstream', raises=(ValueError, TypeError))
def upstream(value):
    if not isinstance(value, str) or any(c.isspace() for c in value) or '\\' in value:
        return False
    parsed = urlsplit(value)
    return parsed.scheme in ('http', 'https') and bool(parsed.hostname) and parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment and (parsed.port is None or 1 <= parsed.port <= 65535)


@CHECKER.checks('agp-path')
def path_prefix(value):
    if not isinstance(value, str) or not value.startswith('/') or '//' in value or '\\' in value:
        return False
    if unquote(value) != value or any(c.isspace() for c in value):
        return False
    return not any(part in ('.', '..') for part in value.split('/'))


@CHECKER.checks('agp-relativepath')
def bundle_path(value):
    return (isinstance(value, str) and 1 <= len(value) <= 256
            and re.fullmatch(r'[A-Za-z0-9/_.+-]+', value) is not None
            and not value.startswith('/') and value not in ('.', '..')
            and not value.startswith('../') and posixpath.normpath(value) == value)


def load_document(path):
    if path.suffix == '.json':
        return json.loads(path.read_text())
    class UniqueLoader(yaml.SafeLoader):
        pass
    def mapping(loader, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError(f'duplicate YAML key {key!r} in {path}')
            result[key] = loader.construct_object(value_node, deep=deep)
        return result
    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    return yaml.load(path.read_text(), Loader=UniqueLoader)


def main():
    schema_paths = sorted((ROOT / 'schemas').glob('*.schema.json'))
    resources = []
    for path in schema_paths:
        data = load_document(path)
        Draft202012Validator.check_schema(data)
        resources.append((path.as_uri(), Resource.from_contents(data)))
    registry = Registry().with_resources(resources)
    api, base_uri = read_from_filename(str(ROOT / 'api/openapi.yaml'))
    validate(api, base_uri=base_uri)
    api_uri = (ROOT / 'api/openapi.yaml').as_uri()
    registry = registry.with_resource(api_uri, Resource.from_contents(api, default_specification=DRAFT202012))
    cases = load_document(ROOT / 'fixtures/cases.json')
    for case in cases:
        if 'apiSchema' in case:
            schema_uri = api_uri + '#/components/schemas/' + case['apiSchema']
        else:
            schema_uri = (ROOT / 'schemas' / (case['schema'] + '.schema.json')).as_uri()
        validator = Draft202012Validator({'$ref': schema_uri + ('#' + case['fragment'] if 'fragment' in case else '')}, registry=registry, format_checker=CHECKER)
        errors = list(validator.iter_errors(load_document(ROOT / case['file'])))
        if bool(errors) == case['valid']:
            raise AssertionError(f"{case['file']}: expected valid={case['valid']}; " + '; '.join(e.message for e in errors[:3]))
        if 'edgeAuthStatus' in case:
            decision = load_document(ROOT / case['file'])
            expected = 204 if decision['decision'] == 'allow' else (401 if decision['reasonCode'] in ('authentication_required', 'session_expired', 'mfa_required') else 403)
            assert expected == case['edgeAuthStatus'], 'inconsistent auth status fixture'
    if load_document(ROOT / 'examples/gateway.yaml') != load_document(ROOT / 'examples/gateway.json'):
        raise AssertionError('YAML and JSON gateway examples differ')
    ids = [op['operationId'] for item in api['paths'].values() for method, op in item.items() if method in ('get', 'post', 'put', 'patch', 'delete')]
    assert len(ids) == len(set(ids)), 'duplicate OpenAPI operationId'
    for route, item in api['paths'].items():
        for method, op in item.items():
            if method not in ('get', 'post', 'put', 'patch', 'delete'):
                continue
            if route.startswith('/api/v2/') and method != 'get':
                assert any(p.get('$ref', '').endswith('/CSRF') for p in op.get('parameters', [])), f'CSRF missing: {method} {route}'
    for path in sorted(ROOT.glob('*.sql')):
        assert parse_sql(path.read_text()), f'empty SQL {path.name}'
    markdown = sorted(ROOT.glob('*.md'))
    for path in markdown:
        content = path.read_text()
        assert content.endswith('\n'), f'missing final newline: {path.name}'
        assert not any(line.rstrip() != line for line in content.splitlines()), f'trailing whitespace: {path.name}'
        assert sum(line.startswith('```') for line in content.splitlines()) % 2 == 0, f'unclosed fence: {path.name}'
        for href in re.findall(r'\]\(([^)\s]+)\)', content):
            if '://' in href or href.startswith('#') or href.startswith('mailto:'):
                continue
            target = href.split('#', 1)[0]
            assert (path.parent / target).exists(), f'broken local link {path.name}: {href}'
    requirements = (ROOT / 'requirements.md').read_text()
    for i in range(1, 29):
        assert f'REQ-{i:02d}' in requirements, f'missing REQ-{i:02d}'
        assert f'REQ-{i:02d}' in (ROOT / 'testing.md').read_text(), f'no test mapping REQ-{i:02d}'
    print(f'PASS: {len(schema_paths)} schemas, {len(cases)} fixture cases, {len(ids)} OpenAPI operations, SQL syntax, {len(markdown)} Markdown documents/links, REQ-01..28 traceability')
    print('NOT CHECKED: cryptographic signatures, runtime services, native PostgreSQL 17, deployment, HA/DR and performance.')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        raise
