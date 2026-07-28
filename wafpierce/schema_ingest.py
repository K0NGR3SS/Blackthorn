"""
WAFPierce Schema Ingestion

Discovers API endpoints and parameters from machine-readable schemas so the
scanner can do targeted, schema-aware fuzzing instead of guessing paths:

  * OpenAPI / Swagger  (v2 and v3)  -> common well-known JSON locations
  * GraphQL introspection           -> queries/mutations + their arguments

Returns endpoints in the same shape the crawler uses:

    {'path': '/api/users', 'params': {'id': 'test'}, 'method': 'GET'}

Stdlib + requests session only; never raises (best-effort discovery).
"""
import json
import logging
from urllib.parse import quote, urlparse, urljoin
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

# Well-known locations where OpenAPI/Swagger docs are commonly served.
OPENAPI_PATHS = [
    '/swagger.json', '/openapi.json', '/v2/swagger.json', '/v3/api-docs',
    '/api-docs', '/api/swagger.json', '/api/openapi.json', '/swagger/v1/swagger.json',
    '/api-docs/swagger.json', '/docs/swagger.json', '/openapi.yaml', '/swagger.yaml',
    '/api/v1/openapi.json', '/.well-known/openapi.json',
]

# Common GraphQL endpoint locations.
GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/v1/graphql', '/query', '/gql']

INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields { name args { name } }
        }
      }
    }
    """
}

_SAMPLE_VALUES = {
    'integer': '1', 'number': '1', 'boolean': 'true', 'string': 'test',
    'array': 'test', 'object': 'test',
}


def _get(session, url, timeout):
    try:
        # Schema discovery shares the authenticated scan session. Redirects are
        # intentionally not followed here so credentials cannot cross origins.
        return session.get(
            url, timeout=timeout, allow_redirects=False, verify=False
        )
    except Exception as e:
        logger.debug(f"Schema GET failed {url}: {e}")
        return None


def _sample_for(schema: dict) -> Any:
    if not isinstance(schema, dict):
        return 'test'
    if schema.get('example') is not None:
        return schema['example']
    if schema.get('default') is not None:
        return schema['default']
    if schema.get('enum'):
        return schema['enum'][0]
    schema_type = schema.get('type', 'string')
    if schema_type == 'object' or schema.get('properties'):
        return {
            name: _sample_for(child)
            for name, child in (schema.get('properties') or {}).items()
        }
    if schema_type == 'array':
        return [_sample_for(schema.get('items') or {})]
    value = _SAMPLE_VALUES.get(schema_type, 'test')
    if schema_type == 'integer':
        return 1
    if schema_type == 'number':
        return 1.0
    if schema_type == 'boolean':
        return True
    return value


def _parse_openapi(doc: dict) -> List[Dict[str, Any]]:
    """Parse an OpenAPI v2/v3 document into endpoints."""
    endpoints = []
    if not isinstance(doc, dict):
        return endpoints

    base_path = doc.get('basePath', '') or ''  # swagger v2
    paths = doc.get('paths', {})
    if not isinstance(paths, dict):
        return endpoints

    for raw_path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        full_path = (base_path.rstrip('/') + '/' + raw_path.lstrip('/')) if base_path else raw_path
        if not full_path.startswith('/'):
            full_path = '/' + full_path
        path_parameters = methods.get('parameters', []) if isinstance(
            methods.get('parameters'), list
        ) else []
        for method, op in methods.items():
            if method.lower() not in ('get', 'post', 'put', 'delete', 'patch'):
                continue
            params = {}
            path_values = {}
            headers = {}
            body = None
            if isinstance(op, dict):
                parameters = list(path_parameters) + list(op.get('parameters', []) or [])
                form_fields = {}
                for p in parameters:
                    if not isinstance(p, dict):
                        continue
                    name = p.get('name')
                    if not name:
                        continue
                    where = p.get('in')
                    sample = _sample_for(p.get('schema', p))
                    if where == 'query':
                        params[name] = sample
                    elif where == 'path':
                        path_values[name] = sample
                    elif where == 'header':
                        headers[name] = str(sample)
                    elif where == 'body':
                        body = json.dumps(sample, separators=(',', ':'))
                        headers['Content-Type'] = 'application/json'
                    elif where == 'formData':
                        form_fields[name] = sample
                if form_fields:
                    body = '&'.join(
                        f'{quote(str(name))}={quote(str(value))}'
                        for name, value in form_fields.items()
                    )
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'

                # OpenAPI 3 requestBody.
                request_body = op.get('requestBody') or {}
                content = request_body.get('content') if isinstance(
                    request_body, dict
                ) else {}
                if isinstance(content, dict) and content:
                    media_type = (
                        'application/json' if 'application/json' in content
                        else next(iter(content))
                    )
                    media = content.get(media_type) or {}
                    sample = media.get('example')
                    if sample is None:
                        sample = _sample_for(media.get('schema') or {})
                    if media_type == 'application/json' and isinstance(
                        sample, (dict, list)
                    ):
                        body = json.dumps(sample, separators=(',', ':'))
                    else:
                        body = str(sample)
                    headers['Content-Type'] = media_type
            resolved_path = full_path
            for name, value in path_values.items():
                resolved_path = resolved_path.replace(
                    '{' + name + '}', quote(str(value), safe='')
                )
            endpoints.append({
                'path': resolved_path,
                'params': params,
                'method': method.upper(),
                'headers': headers,
                'body': body,
                'parameter_location': 'query',
            })
    return endpoints


def ingest_openapi(base_url: str, session, timeout: int = 5) -> List[Dict[str, Any]]:
    endpoints = []
    seen_docs = 0
    for loc in OPENAPI_PATHS:
        url = urljoin(base_url + '/', loc.lstrip('/'))
        resp = _get(session, url, timeout)
        if resp is None or resp.status_code >= 400:
            continue
        ctype = resp.headers.get('Content-Type', '').lower()
        body = resp.text
        doc = None
        if 'json' in ctype or body.lstrip().startswith('{'):
            try:
                doc = json.loads(body)
            except Exception:
                doc = None
        if doc and ('swagger' in doc or 'openapi' in doc or 'paths' in doc):
            parsed = _parse_openapi(doc)
            if parsed:
                logger.info(f"OpenAPI doc at {url}: {len(parsed)} endpoints")
                endpoints.extend(parsed)
                seen_docs += 1
                if seen_docs >= 2:  # one or two docs is plenty
                    break
    return endpoints


def ingest_graphql(base_url: str, session, timeout: int = 5) -> List[Dict[str, Any]]:
    endpoints = []
    for loc in GRAPHQL_PATHS:
        url = urljoin(base_url + '/', loc.lstrip('/'))
        try:
            resp = session.post(
                url, json=INTROSPECTION_QUERY, timeout=timeout,
                allow_redirects=False, verify=False,
            )
        except Exception as e:
            logger.debug(f"GraphQL introspection failed {url}: {e}")
            continue
        if resp is None or resp.status_code >= 400:
            continue
        try:
            data = resp.json()
        except Exception:
            continue
        schema = (data or {}).get('data', {}).get('__schema')
        if not schema:
            continue
        logger.info(f"GraphQL introspection enabled at {url}")
        # Record the endpoint itself + each query/mutation field as a param hint.
        query_type = (schema.get('queryType') or {}).get('name')
        mutation_type = (schema.get('mutationType') or {}).get('name')
        op_fields = []
        for t in schema.get('types', []) or []:
            if t.get('name') in (query_type, mutation_type) and t.get('fields'):
                for f in t['fields']:
                    args = {a['name']: 'test' for a in (f.get('args') or []) if a.get('name')}
                    op_fields.append((f['name'], args))
        gpath = urlparse(url).path or '/graphql'
        # Endpoint with introspection enabled is itself a finding-worthy target.
        endpoints.append({'path': gpath, 'params': {},
                          'method': 'POST', 'graphql': True,
                          'headers': {'Content-Type': 'application/json'},
                          'body': json.dumps({'query': '{__typename}'}),
                          'introspection': True})
        for fname, args in op_fields[:30]:
            query = f'{{{fname}}}'
            endpoints.append({
                'path': gpath, 'params': {},
                'method': 'POST', 'graphql': True, 'field': fname,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'query': query, 'variables': args}),
            })
        break  # one working endpoint is enough
    return endpoints


def ingest_schemas(base_url: str, session, timeout: int = 5) -> List[Dict[str, Any]]:
    """Run all schema discovery and return combined endpoints (never raises)."""
    base_url = base_url.rstrip('/')
    out = []
    try:
        out.extend(ingest_openapi(base_url, session, timeout))
    except Exception as e:
        logger.debug(f"OpenAPI ingest error: {e}")
    try:
        out.extend(ingest_graphql(base_url, session, timeout))
    except Exception as e:
        logger.debug(f"GraphQL ingest error: {e}")
    return out
