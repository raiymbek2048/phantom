"""
API Discovery Module

Discovers and analyzes GraphQL endpoints, Swagger/OpenAPI specs, WADL/WSDL services.
Extracts endpoints, schemas, and reports security misconfigurations.
"""
import asyncio
import json
import re
from urllib.parse import urlencode, urljoin, quote

import httpx

from app.utils.http_client import make_client


# ---------- Constants ----------

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/gql", "/query", "/graphql/v1", "/api/gql",
    "/graphql/console", "/graphiql",
]

OPENAPI_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/v2/api-docs", "/v3/api-docs",
    "/.well-known/openapi.json", "/docs/openapi.json",
    "/api/swagger.json", "/api/openapi.json",
    "/api/v1/swagger.json", "/api/v1/openapi.json",
    "/docs", "/redoc",
    "/api-docs.json", "/swagger-resources",
    "/swagger-ui.html",
]

WADL_WSDL_PATHS = [
    "/application.wadl", "/?wsdl", "/ws?wsdl",
    "/services?wsdl", "/service?wsdl",
]

INTROSPECTION_QUERY = (
    "{__schema{types{name,kind,fields{name,args{name,type{name,kind,ofType{name,kind}}}}}"
    ",queryType{name},mutationType{name},subscriptionType{name}}}"
)

DEPTH_TEST_QUERY = (
    '{"query":"{a:__typename '
    + "".join(f"l{i}:__schema{{types{{name,fields{{name}}}}}}" for i in range(10))
    + '}"}'
)

SENSITIVE_OPS = {
    "createuser", "deleteuser", "removeuser", "login", "signin",
    "resetpassword", "changepassword", "forgotpassword", "register",
    "signup", "uploadfile", "upload", "deleteaccount", "updatepassword",
    "setpassword", "adminlogin", "createadmin", "grantpermission",
    "revoketoken", "generatetoken", "createtoken", "deletetoken",
    "updatepermission", "assignrole", "removerole",
}


# ---------- Main entry points ----------

async def discover_graphql(base_url: str, endpoints: list[dict], context: dict) -> dict:
    """Discover and analyze GraphQL endpoints."""
    result = {
        "endpoint": None,
        "introspection_enabled": False,
        "types_count": 0,
        "queries": [],
        "mutations": [],
        "subscriptions": [],
        "sensitive_operations": [],
        "depth_limit": None,
        "complexity_limit": None,
        "batching_allowed": None,
        "all_types": [],
        "generated_endpoints": [],
    }

    # Build candidate list: known paths + endpoints that look like GraphQL
    candidates = [base_url.rstrip("/") + p for p in GRAPHQL_PATHS]
    for ep in endpoints:
        url = ep.get("url", "").lower()
        if any(kw in url for kw in ("graphql", "graphiql", "/gql", "/query")):
            candidates.append(ep.get("url", ""))

    # Deduplicate preserving order
    seen = set()
    unique = []
    for c in candidates:
        norm = c.rstrip("/").lower()
        if norm not in seen:
            seen.add(norm)
            unique.append(c)
    candidates = unique

    auth_cookie = context.get("auth_cookie")
    custom_headers = context.get("custom_headers", {})

    headers = dict(custom_headers)
    if auth_cookie:
        if auth_cookie.startswith("token="):
            headers["Authorization"] = f"Bearer {auth_cookie.split('=', 1)[1]}"
        else:
            headers["Cookie"] = auth_cookie

    try:
        async with make_client(extra_headers=headers, timeout=15.0) as client:
            # Try introspection on each candidate
            for url in candidates:
                schema = await _try_introspection(client, url)
                if schema:
                    result["endpoint"] = url
                    result["introspection_enabled"] = True
                    _parse_schema(schema, result)
                    break

            if result["endpoint"]:
                gql_url = result["endpoint"]
                # Security checks
                result["depth_limit"] = await _check_depth_limit(client, gql_url)
                result["batching_allowed"] = await _check_batching(client, gql_url)

                # Generate test endpoints from discovered operations
                result["generated_endpoints"] = _generate_graphql_endpoints(
                    gql_url, result["queries"], result["mutations"]
                )
    except Exception:
        pass

    return result


async def discover_openapi(base_url: str, endpoints: list[dict], context: dict) -> dict:
    """Discover and parse Swagger/OpenAPI specifications."""
    result = {
        "spec_url": None,
        "version": None,
        "title": None,
        "endpoints_count": 0,
        "endpoints": [],
        "auth_schemes": [],
        "raw_spec": None,
    }

    candidates = [base_url.rstrip("/") + p for p in OPENAPI_PATHS]
    # Also check discovered endpoints that look like API docs
    for ep in endpoints:
        url = ep.get("url", "").lower()
        if any(kw in url for kw in ("swagger", "openapi", "api-docs", "api-doc")):
            candidates.append(ep.get("url", ""))

    seen = set()
    unique = []
    for c in candidates:
        norm = c.rstrip("/").lower()
        if norm not in seen:
            seen.add(norm)
            unique.append(c)
    candidates = unique

    auth_cookie = context.get("auth_cookie")
    custom_headers = context.get("custom_headers", {})
    headers = dict(custom_headers)
    if auth_cookie:
        if auth_cookie.startswith("token="):
            headers["Authorization"] = f"Bearer {auth_cookie.split('=', 1)[1]}"
        else:
            headers["Cookie"] = auth_cookie

    try:
        async with make_client(extra_headers=headers, timeout=15.0) as client:
            for url in candidates:
                spec = await _try_fetch_openapi(client, url)
                if spec:
                    result["spec_url"] = url
                    result["raw_spec"] = spec
                    _parse_openapi_spec(spec, base_url, result)
                    break
    except Exception:
        pass

    return result


async def discover_wadl_wsdl(base_url: str, context: dict) -> dict:
    """Discover WADL/WSDL service definitions."""
    result = {
        "found": False,
        "type": None,
        "url": None,
        "endpoints": [],
    }

    candidates = [base_url.rstrip("/") + p for p in WADL_WSDL_PATHS]

    auth_cookie = context.get("auth_cookie")
    custom_headers = context.get("custom_headers", {})
    headers = dict(custom_headers)
    if auth_cookie:
        if auth_cookie.startswith("token="):
            headers["Authorization"] = f"Bearer {auth_cookie.split('=', 1)[1]}"
        else:
            headers["Cookie"] = auth_cookie

    try:
        async with make_client(extra_headers=headers, timeout=10.0) as client:
            for url in candidates:
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and len(resp.text) > 50:
                        content = resp.text.strip()
                        if "<?xml" in content[:100] or "<wsdl:" in content or "<wadl:" in content:
                            if "<wsdl:" in content or "wsdl" in url.lower():
                                result["type"] = "wsdl"
                            elif "<wadl:" in content or "wadl" in url.lower():
                                result["type"] = "wadl"
                            else:
                                result["type"] = "xml_service"

                            result["found"] = True
                            result["url"] = url
                            result["endpoints"] = _parse_xml_service(content, base_url)
                            break
                except (httpx.TimeoutException, httpx.ConnectError):
                    continue
    except Exception:
        pass

    return result


async def run_api_discovery(base_url: str, endpoints: list[dict], context: dict) -> dict:
    """Run all API discovery modules and aggregate results.

    Returns dict with graphql, openapi, wadl_wsdl, findings, and new_endpoints.
    """
    graphql_result, openapi_result, wadl_result = await asyncio.gather(
        discover_graphql(base_url, endpoints, context),
        discover_openapi(base_url, endpoints, context),
        discover_wadl_wsdl(base_url, context),
        return_exceptions=True,
    )

    # Handle exceptions gracefully
    if isinstance(graphql_result, Exception):
        graphql_result = {"endpoint": None, "introspection_enabled": False}
    if isinstance(openapi_result, Exception):
        openapi_result = {"spec_url": None, "endpoints": []}
    if isinstance(wadl_result, Exception):
        wadl_result = {"found": False}

    # Build findings
    findings = []
    new_endpoints = []

    # --- GraphQL findings ---
    if graphql_result.get("introspection_enabled"):
        findings.append({
            "title": "GraphQL introspection enabled",
            "severity": "medium",
            "vuln_type": "misconfiguration",
            "description": (
                f"GraphQL introspection is enabled at {graphql_result['endpoint']}. "
                f"This exposes the entire API schema including {graphql_result.get('types_count', 0)} types, "
                f"{len(graphql_result.get('queries', []))} queries, and "
                f"{len(graphql_result.get('mutations', []))} mutations. "
                "Attackers can use this to map the entire API surface."
            ),
            "endpoint": graphql_result["endpoint"],
            "evidence": json.dumps({
                "types_count": graphql_result.get("types_count", 0),
                "queries": graphql_result.get("queries", [])[:20],
                "mutations": graphql_result.get("mutations", [])[:20],
            }),
            "remediation": "Disable introspection in production by configuring your GraphQL server.",
        })

        if graphql_result.get("sensitive_operations"):
            findings.append({
                "title": "GraphQL exposes sensitive operations",
                "severity": "high",
                "vuln_type": "info_disclosure",
                "description": (
                    f"Sensitive operations found in GraphQL schema: "
                    f"{', '.join(graphql_result['sensitive_operations'][:10])}. "
                    "These may allow unauthorized access to critical functionality."
                ),
                "endpoint": graphql_result["endpoint"],
                "evidence": json.dumps({
                    "sensitive_operations": graphql_result["sensitive_operations"],
                }),
                "remediation": (
                    "Implement proper authorization checks on all sensitive mutations. "
                    "Disable introspection in production."
                ),
            })

        if graphql_result.get("depth_limit") is None:
            findings.append({
                "title": "GraphQL has no query depth limit",
                "severity": "medium",
                "vuln_type": "misconfiguration",
                "description": (
                    f"GraphQL endpoint {graphql_result['endpoint']} does not enforce a query depth limit. "
                    "An attacker can send deeply nested queries to cause Denial of Service."
                ),
                "endpoint": graphql_result["endpoint"],
                "evidence": "Deeply nested introspection query (10 levels) succeeded without error.",
                "remediation": "Implement query depth limiting (recommended max 7-10 levels).",
            })

        if graphql_result.get("batching_allowed"):
            findings.append({
                "title": "GraphQL query batching allowed",
                "severity": "low",
                "vuln_type": "misconfiguration",
                "description": (
                    f"GraphQL endpoint {graphql_result['endpoint']} allows query batching. "
                    "This can be used to bypass rate limiting or brute-force authentication "
                    "by sending multiple queries in a single HTTP request."
                ),
                "endpoint": graphql_result["endpoint"],
                "evidence": "Array of queries accepted and processed.",
                "remediation": "Disable query batching or limit the number of queries per batch.",
            })

        # Add generated endpoints
        new_endpoints.extend(graphql_result.get("generated_endpoints", []))

    # --- OpenAPI findings ---
    if openapi_result.get("spec_url"):
        findings.append({
            "title": "API documentation publicly accessible",
            "severity": "low",
            "vuln_type": "info_disclosure",
            "description": (
                f"OpenAPI/Swagger specification found at {openapi_result['spec_url']}. "
                f"Version: {openapi_result.get('version', 'unknown')}. "
                f"Exposes {openapi_result.get('endpoints_count', 0)} API endpoints. "
                "Attackers can use this to understand the full API surface."
            ),
            "endpoint": openapi_result["spec_url"],
            "evidence": json.dumps({
                "version": openapi_result.get("version"),
                "title": openapi_result.get("title"),
                "endpoints_count": openapi_result.get("endpoints_count", 0),
                "auth_schemes": openapi_result.get("auth_schemes", []),
            }),
            "remediation": (
                "Restrict access to API documentation in production environments. "
                "Use authentication/IP allowlisting."
            ),
        })

        # Add spec endpoints
        new_endpoints.extend(openapi_result.get("endpoints", []))

    # --- WADL/WSDL findings ---
    if wadl_result.get("found"):
        findings.append({
            "title": f"{(wadl_result.get('type') or 'service').upper()} service definition exposed",
            "severity": "low",
            "vuln_type": "info_disclosure",
            "description": (
                f"Service definition ({wadl_result.get('type', 'unknown')}) found at {wadl_result['url']}. "
                f"Exposes {len(wadl_result.get('endpoints', []))} service endpoints."
            ),
            "endpoint": wadl_result["url"],
            "evidence": json.dumps({
                "type": wadl_result.get("type"),
                "endpoints": wadl_result.get("endpoints", [])[:10],
            }),
            "remediation": "Restrict access to service definitions in production.",
        })
        new_endpoints.extend(wadl_result.get("endpoints", []))

    # Remove raw_spec from result to keep context size manageable (store it separately)
    graphql_schema_for_context = None
    if graphql_result.get("introspection_enabled"):
        graphql_schema_for_context = {
            "endpoint": graphql_result.get("endpoint"),
            "types": graphql_result.get("all_types", [])[:100],
            "queries": graphql_result.get("queries"),
            "mutations": graphql_result.get("mutations"),
            "sensitive_operations": graphql_result.get("sensitive_operations"),
        }

    openapi_summary = dict(openapi_result)
    openapi_summary.pop("raw_spec", None)

    return {
        "graphql": graphql_result,
        "openapi": openapi_summary,
        "wadl_wsdl": wadl_result,
        "findings": findings,
        "new_endpoints": new_endpoints,
        "graphql_schema": graphql_schema_for_context,
    }


# ---------- Internal helpers ----------

async def _try_introspection(client: httpx.AsyncClient, url: str) -> dict | None:
    """Try to run introspection query via POST and GET."""
    # POST with JSON body
    try:
        resp = await client.post(
            url,
            json={"query": INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            schema = (data.get("data") or {}).get("__schema")
            if schema:
                return schema
    except (httpx.TimeoutException, httpx.ConnectError, json.JSONDecodeError, Exception):
        pass

    # GET with query parameter
    try:
        resp = await client.get(url, params={"query": INTROSPECTION_QUERY})
        if resp.status_code == 200:
            data = resp.json()
            schema = (data.get("data") or {}).get("__schema")
            if schema:
                return schema
    except (httpx.TimeoutException, httpx.ConnectError, json.JSONDecodeError, Exception):
        pass

    return None


def _parse_schema(schema: dict, result: dict):
    """Parse introspection schema into structured result."""
    types = schema.get("types") or []
    query_type_name = (schema.get("queryType") or {}).get("name", "Query")
    mutation_type_name = (schema.get("mutationType") or {}).get("name", "Mutation")
    subscription_type_name = (schema.get("subscriptionType") or {}).get("name", "Subscription")

    # Filter out built-in types (starting with __)
    user_types = [t for t in types if not t.get("name", "").startswith("__")]
    result["types_count"] = len(user_types)
    result["all_types"] = [
        {
            "name": t.get("name"),
            "kind": t.get("kind"),
            "fields": [
                {
                    "name": f.get("name"),
                    "args": [a.get("name") for a in (f.get("args") or [])],
                }
                for f in (t.get("fields") or [])
            ],
        }
        for t in user_types[:150]
    ]

    # Extract queries, mutations, subscriptions
    for t in types:
        name = t.get("name", "")
        fields = t.get("fields") or []
        field_names = [f.get("name") for f in fields if f.get("name")]

        if name == query_type_name:
            result["queries"] = field_names
        elif name == mutation_type_name:
            result["mutations"] = field_names
        elif name == subscription_type_name:
            result["subscriptions"] = field_names

    # Detect sensitive operations
    all_ops = result["queries"] + result["mutations"]
    result["sensitive_operations"] = [
        op for op in all_ops
        if op.lower() in SENSITIVE_OPS
        or any(s in op.lower() for s in (
            "delete", "remove", "admin", "password", "token",
            "secret", "key", "credential", "permission", "role",
            "upload", "exec", "execute", "shell", "command",
        ))
    ]


async def _check_depth_limit(client: httpx.AsyncClient, url: str) -> int | None:
    """Check if GraphQL enforces a query depth limit.

    Returns the depth limit integer if limited, or None if no limit detected.
    """
    # Build a deeply nested query (10 levels)
    nested = '{"query":"{' + INTROSPECTION_QUERY.replace('"', '\\"') + '}"}'
    # Simpler: just send a deeply nested __typename query
    deep_query = "__typename"
    for i in range(10):
        deep_query = f"__schema{{types{{name,fields{{name}}}}}}"

    try:
        resp = await client.post(
            url,
            json={"query": "{" + " ".join(f"l{i}:__schema{{types{{name,fields{{name}}}}}}" for i in range(10)) + "}"},
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            errors = data.get("errors", [])
            # If errors mention depth limit, extract the limit
            for err in errors:
                msg = (err.get("message") or "").lower()
                if "depth" in msg or "too complex" in msg or "max" in msg:
                    # Try to extract number
                    nums = re.findall(r'\d+', err.get("message", ""))
                    if nums:
                        return int(nums[0])
                    return 0  # Has limit but unknown value
            # If we got data back without depth errors, no limit
            if data.get("data"):
                return None
    except Exception:
        pass

    return None  # Can't determine


async def _check_batching(client: httpx.AsyncClient, url: str) -> bool | None:
    """Check if GraphQL allows query batching (array of queries)."""
    batch = [
        {"query": "{__typename}"},
        {"query": "{__typename}"},
    ]
    try:
        resp = await client.post(
            url,
            json=batch,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            # If response is a list, batching is allowed
            if isinstance(data, list) and len(data) >= 2:
                return True
            return False
    except Exception:
        pass
    return None


def _generate_graphql_endpoints(gql_url: str, queries: list, mutations: list) -> list[dict]:
    """Generate test endpoint entries for discovered GraphQL operations."""
    endpoints = []
    for q in queries:
        endpoints.append({
            "url": gql_url,
            "method": "POST",
            "type": "api",
            "interest": "high",
            "source": "graphql_introspection",
            "graphql_operation": q,
            "graphql_type": "query",
            "params": [],
        })
    for m in mutations:
        interest = "critical" if m.lower() in SENSITIVE_OPS or any(
            s in m.lower() for s in ("delete", "admin", "password", "upload", "exec")
        ) else "high"
        endpoints.append({
            "url": gql_url,
            "method": "POST",
            "type": "api",
            "interest": interest,
            "source": "graphql_introspection",
            "graphql_operation": m,
            "graphql_type": "mutation",
            "params": [],
        })
    return endpoints


async def _try_fetch_openapi(client: httpx.AsyncClient, url: str) -> dict | None:
    """Fetch and validate an OpenAPI/Swagger spec."""
    try:
        resp = await client.get(url)
        if resp.status_code != 200:
            return None

        content_type = resp.headers.get("content-type", "")
        text = resp.text.strip()

        # Direct JSON response
        if "json" in content_type or text.startswith("{"):
            try:
                spec = resp.json()
                # Validate it's actually an OpenAPI spec
                if _is_openapi_spec(spec):
                    return spec
            except json.JSONDecodeError:
                pass

        # HTML page that might link to actual spec (e.g., /docs, /swagger-ui.html)
        if "html" in content_type or text.startswith("<!"):
            # Look for spec URL in the HTML
            spec_urls = re.findall(
                r'(?:url|spec-url|configUrl)["\s:=]+["\']?([^"\'>\s]+\.json[^"\'>\s]*)',
                text, re.IGNORECASE,
            )
            for spec_url in spec_urls[:3]:
                if spec_url.startswith("/"):
                    # Extract base from the original URL
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    full_url = f"{parsed.scheme}://{parsed.netloc}{spec_url}"
                elif spec_url.startswith("http"):
                    full_url = spec_url
                else:
                    full_url = url.rsplit("/", 1)[0] + "/" + spec_url

                try:
                    resp2 = await client.get(full_url)
                    if resp2.status_code == 200:
                        spec = resp2.json()
                        if _is_openapi_spec(spec):
                            return spec
                except Exception:
                    continue

        # YAML spec (try parsing)
        if "yaml" in content_type or "yml" in content_type:
            try:
                import yaml
                spec = yaml.safe_load(text)
                if isinstance(spec, dict) and _is_openapi_spec(spec):
                    return spec
            except Exception:
                pass

    except (httpx.TimeoutException, httpx.ConnectError):
        pass
    except Exception:
        pass

    return None


def _is_openapi_spec(spec: dict) -> bool:
    """Validate that a dict looks like an OpenAPI/Swagger spec."""
    if not isinstance(spec, dict):
        return False
    # Swagger 2.0
    if spec.get("swagger") and spec.get("paths"):
        return True
    # OpenAPI 3.x
    if spec.get("openapi") and spec.get("paths"):
        return True
    # Minimal: has info and paths
    if spec.get("info") and spec.get("paths"):
        return True
    return False


def _parse_openapi_spec(spec: dict, base_url: str, result: dict):
    """Parse OpenAPI/Swagger spec into structured result."""
    # Version
    result["version"] = spec.get("openapi") or spec.get("swagger") or "unknown"
    result["title"] = (spec.get("info") or {}).get("title")

    # Determine base path
    if spec.get("openapi", "").startswith("3"):
        # OpenAPI 3.x: servers
        servers = spec.get("servers") or []
        if servers:
            server_url = servers[0].get("url", "")
            if server_url.startswith("http"):
                api_base = server_url.rstrip("/")
            elif server_url.startswith("/"):
                api_base = base_url.rstrip("/") + server_url.rstrip("/")
            else:
                api_base = base_url.rstrip("/")
        else:
            api_base = base_url.rstrip("/")
    else:
        # Swagger 2.0: basePath
        base_path = spec.get("basePath", "").rstrip("/")
        host = spec.get("host", "")
        schemes = spec.get("schemes", ["https"])
        if host:
            api_base = f"{schemes[0]}://{host}{base_path}"
        else:
            api_base = base_url.rstrip("/") + base_path

    # Auth schemes
    auth_schemes = set()
    # OpenAPI 3.x
    security_schemes = (spec.get("components") or {}).get("securitySchemes") or {}
    # Swagger 2.0
    if not security_schemes:
        security_schemes = spec.get("securityDefinitions") or {}

    for name, scheme in security_schemes.items():
        scheme_type = scheme.get("type", "").lower()
        if scheme_type == "apikey":
            auth_schemes.add("apiKey")
        elif scheme_type == "http":
            bearer_scheme = scheme.get("scheme", "").lower()
            auth_schemes.add(bearer_scheme if bearer_scheme else "http")
        elif scheme_type == "oauth2":
            auth_schemes.add("oauth2")
        elif scheme_type == "openidconnect":
            auth_schemes.add("openIdConnect")
        else:
            auth_schemes.add(scheme_type)

    result["auth_schemes"] = list(auth_schemes)

    # Parse paths
    endpoints = []
    paths = spec.get("paths") or {}

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        for method, operation in methods.items():
            method_upper = method.upper()
            if method_upper not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                continue
            if not isinstance(operation, dict):
                continue

            full_url = api_base + path

            # Extract parameters
            params = []
            # Path-level params
            for p in methods.get("parameters", []):
                if isinstance(p, dict):
                    params.append(_extract_param(p))
            # Operation-level params
            for p in operation.get("parameters", []):
                if isinstance(p, dict):
                    params.append(_extract_param(p))

            # Check auth requirement
            security = operation.get("security", spec.get("security"))
            auth_required = bool(security)

            # Request body (OpenAPI 3.x)
            request_body = operation.get("requestBody")
            body_schema = None
            if request_body and isinstance(request_body, dict):
                content = request_body.get("content") or {}
                for ct, media in content.items():
                    if isinstance(media, dict) and media.get("schema"):
                        body_schema = _simplify_schema(media["schema"])
                        break

            endpoint = {
                "url": full_url,
                "method": method_upper,
                "type": "api",
                "interest": "high",
                "params": [p.get("name", "") for p in params if p.get("name")],
                "param_details": params,
                "auth_required": auth_required,
                "source": "openapi_spec",
                "summary": operation.get("summary", ""),
            }
            if body_schema:
                endpoint["body_schema"] = body_schema

            endpoints.append(endpoint)

    result["endpoints"] = endpoints
    result["endpoints_count"] = len(endpoints)


def _extract_param(p: dict) -> dict:
    """Extract parameter info from OpenAPI param object."""
    param_type = "string"
    schema = p.get("schema") or {}
    if isinstance(schema, dict):
        param_type = schema.get("type", "string")

    return {
        "name": p.get("name", ""),
        "in": p.get("in", "query"),
        "type": param_type,
        "required": p.get("required", False),
    }


def _simplify_schema(schema: dict, depth: int = 0) -> dict:
    """Simplify OpenAPI schema for storage (avoid deep nesting)."""
    if depth > 3 or not isinstance(schema, dict):
        return {"type": "object"}

    result = {"type": schema.get("type", "object")}

    if schema.get("properties") and isinstance(schema["properties"], dict):
        result["properties"] = {}
        for name, prop in list(schema["properties"].items())[:20]:
            if isinstance(prop, dict):
                result["properties"][name] = {
                    "type": prop.get("type", "string"),
                }

    if schema.get("items") and isinstance(schema["items"], dict):
        result["items"] = _simplify_schema(schema["items"], depth + 1)

    return result


def _parse_xml_service(content: str, base_url: str) -> list[dict]:
    """Parse WADL/WSDL XML to extract endpoints."""
    endpoints = []

    # WSDL: extract service ports and operations
    # Find service locations
    locations = re.findall(r'location=["\']([^"\']+)["\']', content, re.IGNORECASE)
    for loc in locations:
        if loc.startswith("http"):
            endpoints.append({
                "url": loc,
                "method": "POST",
                "type": "api",
                "interest": "high",
                "source": "wsdl",
                "params": [],
            })

    # WSDL operations
    operations = re.findall(r'<(?:wsdl:)?operation\s+name=["\']([^"\']+)["\']', content, re.IGNORECASE)
    for op in operations:
        endpoints.append({
            "url": base_url.rstrip("/") + "/" + op,
            "method": "POST",
            "type": "api",
            "interest": "high",
            "source": "wsdl",
            "soap_operation": op,
            "params": [],
        })

    # WADL: extract resources
    resources = re.findall(r'<resource\s+path=["\']([^"\']+)["\']', content, re.IGNORECASE)
    for res in resources:
        full_url = base_url.rstrip("/") + "/" + res.lstrip("/")
        # Find methods for this resource
        endpoints.append({
            "url": full_url,
            "method": "GET",
            "type": "api",
            "interest": "high",
            "source": "wadl",
            "params": [],
        })

    return endpoints
