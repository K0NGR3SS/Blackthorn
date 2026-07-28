"""Schema-ingestion accuracy guards."""

import json

from wafpierce.schema_ingest import _parse_openapi


def test_openapi_resolves_path_query_and_json_body_inputs():
    document = {
        'openapi': '3.0.3',
        'paths': {
            '/users/{user_id}': {
                'post': {
                    'parameters': [
                        {
                            'name': 'user_id', 'in': 'path', 'required': True,
                            'schema': {'type': 'integer', 'example': 42},
                        },
                        {
                            'name': 'preview', 'in': 'query',
                            'schema': {'type': 'boolean', 'default': False},
                        },
                    ],
                    'requestBody': {
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'display_name': {'type': 'string'},
                                        'admin': {'type': 'boolean'},
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    }

    endpoint = _parse_openapi(document)[0]

    assert endpoint['path'] == '/users/42'
    assert endpoint['params'] == {'preview': False}
    assert endpoint['method'] == 'POST'
    assert endpoint['headers']['Content-Type'] == 'application/json'
    assert json.loads(endpoint['body']) == {
        'display_name': 'test',
        'admin': True,
    }
