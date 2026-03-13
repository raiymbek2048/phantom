"""
Application Graph Builder Module

Builds a structured application model / attack graph from discovered endpoints.
Analyzes flat endpoint lists and produces:
- Entities (users, posts, orders, etc.) with CRUD operations
- Relationships between entities (user has orders, order has items)
- API patterns (REST, GraphQL, RPC)
- Authentication flows
- High-value attack paths (admin takeover, IDOR chains, payment abuse)

Pure heuristic — no AI required. Output stored in context["application_graph"]
for downstream AI analysis phases.
"""
import logging
import re
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

# Patterns that indicate ID segments in URL paths
ID_PATTERNS = [
    re.compile(r'^\d+$'),                                      # numeric: 123
    re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I),  # UUID
    re.compile(r'^[0-9a-f]{24}$', re.I),                       # MongoDB ObjectId
    re.compile(r'^\{[^}]+\}$'),                                # path param placeholder: {id}
    re.compile(r'^:[a-zA-Z_]+$'),                              # Express-style: :id
    re.compile(r'^<[^>]+>$'),                                  # Flask-style: <id>
]

# Segments to skip when extracting entities
SKIP_SEGMENTS = {
    'api', 'v1', 'v2', 'v3', 'v4', 'rest', 'graphql', 'rpc',
    'public', 'private', 'internal', 'external', 'web', 'app',
    'swagger', 'docs', 'redoc', 'openapi', 'health', 'status',
    'metrics', 'actuator', 'debug', 'test',
}

# Auth-related path keywords
AUTH_KEYWORDS = {
    'login', 'signin', 'sign-in', 'sign_in', 'authenticate',
    'auth', 'oauth', 'oauth2', 'oidc', 'sso',
    'token', 'tokens', 'refresh', 'refresh-token',
    'register', 'signup', 'sign-up', 'sign_up', 'registration',
    'logout', 'signout', 'sign-out', 'sign_out',
    'password', 'reset-password', 'forgot-password', 'change-password',
    'verify', 'verify-email', 'confirm', 'activate',
    'mfa', '2fa', 'totp', 'otp',
    'session', 'sessions', 'callback', 'authorize',
    'api-key', 'api-keys', 'apikey', 'apikeys',
}

# High-value endpoint keywords for attack path generation
ADMIN_KEYWORDS = {'admin', 'administrator', 'management', 'manage', 'dashboard', 'panel', 'console', 'superuser'}
PAYMENT_KEYWORDS = {'payment', 'payments', 'pay', 'checkout', 'billing', 'invoice', 'invoices', 'charge', 'subscription', 'subscriptions', 'cart', 'order', 'orders', 'wallet', 'balance', 'refund', 'transaction', 'transactions', 'price', 'pricing'}
UPLOAD_KEYWORDS = {'upload', 'uploads', 'file', 'files', 'attachment', 'attachments', 'media', 'image', 'images', 'document', 'documents', 'import'}
SENSITIVE_KEYWORDS = {'settings', 'config', 'configuration', 'env', 'secret', 'secrets', 'key', 'keys', 'credential', 'credentials', 'export', 'backup', 'dump', 'download'}

# Plural → singular normalization for entity matching
IRREGULAR_PLURALS = {
    'people': 'person', 'children': 'child', 'mice': 'mouse',
    'data': 'datum', 'media': 'medium', 'analyses': 'analysis',
    'statuses': 'status', 'addresses': 'address', 'categories': 'category',
    'companies': 'company', 'policies': 'policy', 'entries': 'entry',
}


def _singularize(word: str) -> str:
    """Simple singularization for entity normalization."""
    lower = word.lower()
    if lower in IRREGULAR_PLURALS:
        return IRREGULAR_PLURALS[lower]
    if lower.endswith('ies') and len(lower) > 4:
        return lower[:-3] + 'y'
    if lower.endswith('ses') or lower.endswith('xes') or lower.endswith('zes'):
        return lower[:-2]
    if lower.endswith('s') and not lower.endswith('ss'):
        return lower[:-1]
    return lower


def _is_id_segment(segment: str) -> bool:
    """Check if a URL path segment looks like an ID/placeholder."""
    return any(p.match(segment) for p in ID_PATTERNS)


def _normalize_endpoint(ep) -> dict:
    """Normalize an endpoint to a dict with url, method, params, status_code."""
    if isinstance(ep, str):
        return {'url': ep, 'method': 'GET', 'params': [], 'status_code': None}
    if isinstance(ep, dict):
        url = ep.get('url') or ep.get('path') or ep.get('endpoint', '')
        method = (ep.get('method') or 'GET').upper()
        params = ep.get('params') or ep.get('parameters') or []
        status = ep.get('status_code') or ep.get('status')
        return {'url': url, 'method': method, 'params': params, 'status_code': status}
    return {'url': str(ep), 'method': 'GET', 'params': [], 'status_code': None}


class ApplicationGraphBuilder:
    """Builds an application model / attack graph from discovered endpoints."""

    def __init__(self, context: dict):
        self.context = context
        self.graph = {
            "entities": {},       # entity_name -> {endpoints: [], methods: [], params: [], crud: {}}
            "relationships": [],  # [{from, to, type, via_endpoint}]
            "auth_flows": [],     # [{type, endpoints, tokens}]
            "attack_paths": [],   # [{name, risk, steps: [{endpoint, method, action}]}]
            "api_patterns": {},   # {pattern_name: [endpoints]}
        }
        self._raw_endpoints = []

    async def build(self) -> dict:
        """Build application graph from discovered endpoints.

        Returns the graph dict, also accessible via self.graph.
        """
        endpoints = self.context.get("endpoints") or []
        if not endpoints:
            logger.info("No endpoints found in context, returning empty graph")
            return self.graph

        self._raw_endpoints = [_normalize_endpoint(ep) for ep in endpoints]
        logger.info("Building application graph from %d endpoints", len(self._raw_endpoints))

        try:
            self._extract_entities()
        except Exception:
            logger.exception("Error extracting entities")

        try:
            self._find_relationships()
        except Exception:
            logger.exception("Error finding relationships")

        try:
            self._detect_auth_flows()
        except Exception:
            logger.exception("Error detecting auth flows")

        try:
            self._detect_api_patterns()
        except Exception:
            logger.exception("Error detecting API patterns")

        try:
            self._build_attack_paths()
        except Exception:
            logger.exception("Error building attack paths")

        entity_count = len(self.graph["entities"])
        rel_count = len(self.graph["relationships"])
        path_count = len(self.graph["attack_paths"])
        logger.info(
            "Application graph built: %d entities, %d relationships, %d attack paths",
            entity_count, rel_count, path_count,
        )

        return self.graph

    # ------------------------------------------------------------------
    # Entity extraction
    # ------------------------------------------------------------------

    def _extract_entities(self):
        """Parse URL paths to discover entities and group endpoints."""
        entities = defaultdict(lambda: {
            "endpoints": [],
            "methods": set(),
            "params": set(),
            "crud": {},  # method -> [endpoints]
            "has_id_access": False,
        })

        for ep in self._raw_endpoints:
            url = ep["url"]
            method = ep["method"]
            params = ep["params"]

            parsed = urlparse(url)
            path = parsed.path.rstrip("/")
            if not path:
                continue

            segments = [s for s in path.split("/") if s]

            # Extract entity names from path segments
            entity_chain = []
            for i, seg in enumerate(segments):
                seg_lower = seg.lower()

                if seg_lower in SKIP_SEGMENTS:
                    continue
                if _is_id_segment(seg):
                    # Mark previous entity as having ID-level access
                    if entity_chain:
                        entities[entity_chain[-1]]["has_id_access"] = True
                    continue

                # This segment is likely an entity name
                entity_name = _singularize(seg_lower)
                entity_chain.append(entity_name)

                entity = entities[entity_name]
                entity["endpoints"].append(url)
                entity["methods"].add(method)

                # Map HTTP methods to CRUD operations
                crud_map = {"GET": "read", "POST": "create", "PUT": "update", "PATCH": "update", "DELETE": "delete"}
                crud_op = crud_map.get(method, method.lower())
                if crud_op not in entity["crud"]:
                    entity["crud"][crud_op] = []
                entity["crud"][crud_op].append(url)

            # Track parameters
            if entity_chain:
                primary_entity = entity_chain[-1]
                if isinstance(params, list):
                    for p in params:
                        pname = p if isinstance(p, str) else (p.get("name", "") if isinstance(p, dict) else str(p))
                        if pname:
                            entities[primary_entity]["params"].add(pname)
                # Also extract query params from URL
                for key in parse_qs(parsed.query).keys():
                    entities[primary_entity]["params"].add(key)

            # Store entity chain for relationship detection
            if len(entity_chain) >= 2:
                for j in range(len(entity_chain) - 1):
                    parent = entity_chain[j]
                    child = entity_chain[j + 1]
                    rel = {
                        "from": parent,
                        "to": child,
                        "type": "has_many",
                        "via_endpoint": url,
                    }
                    # Avoid duplicate relationships
                    if not any(
                        r["from"] == rel["from"] and r["to"] == rel["to"]
                        for r in self.graph["relationships"]
                    ):
                        self.graph["relationships"].append(rel)

        # Convert sets to lists for JSON serialization
        for name, data in entities.items():
            self.graph["entities"][name] = {
                "endpoints": list(set(data["endpoints"])),
                "methods": sorted(data["methods"]),
                "params": sorted(data["params"]),
                "crud": {k: list(set(v)) for k, v in data["crud"].items()},
                "has_id_access": data["has_id_access"],
            }

    # ------------------------------------------------------------------
    # Relationship detection
    # ------------------------------------------------------------------

    def _find_relationships(self):
        """Detect relationships from reference parameters and shared naming."""
        entity_names = set(self.graph["entities"].keys())

        # Detect reference parameters (e.g., user_id → references "user" entity)
        for entity_name, entity_data in self.graph["entities"].items():
            for param in entity_data["params"]:
                param_lower = param.lower()
                # Check if param references another entity: user_id, userId, order-id
                ref_name = None
                for suffix in ("_id", "id", "_uuid", "_pk", "_key", "_ref"):
                    if param_lower.endswith(suffix):
                        candidate = param_lower[: -len(suffix)].rstrip("_").rstrip("-")
                        candidate = _singularize(candidate)
                        if candidate and candidate in entity_names and candidate != entity_name:
                            ref_name = candidate
                            break

                if ref_name:
                    rel = {
                        "from": entity_name,
                        "to": ref_name,
                        "type": "references",
                        "via_endpoint": f"param:{param}",
                    }
                    if not any(
                        r["from"] == rel["from"] and r["to"] == rel["to"] and r["type"] == "references"
                        for r in self.graph["relationships"]
                    ):
                        self.graph["relationships"].append(rel)

    # ------------------------------------------------------------------
    # Auth flow detection
    # ------------------------------------------------------------------

    def _detect_auth_flows(self):
        """Identify authentication flows from endpoint patterns."""
        auth_endpoints = defaultdict(list)  # category -> [endpoints]

        for ep in self._raw_endpoints:
            url = ep["url"]
            parsed = urlparse(url)
            path_lower = parsed.path.lower()
            segments = {s.lower() for s in parsed.path.split("/") if s}

            matched_keywords = segments & AUTH_KEYWORDS
            if not matched_keywords:
                # Also check if any segment contains an auth keyword
                for seg in segments:
                    for kw in AUTH_KEYWORDS:
                        if kw in seg:
                            matched_keywords.add(kw)
                            break

            if not matched_keywords:
                continue

            # Categorize
            if matched_keywords & {'login', 'signin', 'sign-in', 'sign_in', 'authenticate'}:
                auth_endpoints["login"].append({"url": url, "method": ep["method"]})
            elif matched_keywords & {'register', 'signup', 'sign-up', 'sign_up', 'registration'}:
                auth_endpoints["registration"].append({"url": url, "method": ep["method"]})
            elif matched_keywords & {'logout', 'signout', 'sign-out', 'sign_out'}:
                auth_endpoints["logout"].append({"url": url, "method": ep["method"]})
            elif matched_keywords & {'oauth', 'oauth2', 'oidc', 'sso', 'authorize', 'callback'}:
                auth_endpoints["oauth"].append({"url": url, "method": ep["method"]})
            elif matched_keywords & {'token', 'tokens', 'refresh', 'refresh-token'}:
                auth_endpoints["token"].append({"url": url, "method": ep["method"]})
            elif matched_keywords & {'password', 'reset-password', 'forgot-password', 'change-password'}:
                auth_endpoints["password_reset"].append({"url": url, "method": ep["method"]})
            elif matched_keywords & {'mfa', '2fa', 'totp', 'otp'}:
                auth_endpoints["mfa"].append({"url": url, "method": ep["method"]})
            elif matched_keywords & {'api-key', 'api-keys', 'apikey', 'apikeys'}:
                auth_endpoints["api_key"].append({"url": url, "method": ep["method"]})
            elif matched_keywords & {'verify', 'verify-email', 'confirm', 'activate'}:
                auth_endpoints["verification"].append({"url": url, "method": ep["method"]})
            elif matched_keywords & {'session', 'sessions'}:
                auth_endpoints["session"].append({"url": url, "method": ep["method"]})

        # Build auth flow objects
        for flow_type, endpoints in auth_endpoints.items():
            # Infer token types from the flow
            tokens = []
            if flow_type in ("login", "token", "oauth"):
                tokens = ["bearer_token", "session_cookie"]
            elif flow_type == "api_key":
                tokens = ["api_key"]
            elif flow_type == "session":
                tokens = ["session_cookie"]

            self.graph["auth_flows"].append({
                "type": flow_type,
                "endpoints": endpoints,
                "tokens": tokens,
            })

        # Build composite auth chain if login + registration both exist
        if "login" in auth_endpoints and "registration" in auth_endpoints:
            chain_endpoints = auth_endpoints["registration"] + auth_endpoints["login"]
            if "token" in auth_endpoints:
                chain_endpoints += auth_endpoints["token"]
            self.graph["auth_flows"].append({
                "type": "full_auth_chain",
                "endpoints": chain_endpoints,
                "tokens": ["bearer_token", "session_cookie"],
            })

    # ------------------------------------------------------------------
    # API pattern detection
    # ------------------------------------------------------------------

    def _detect_api_patterns(self):
        """Detect REST, GraphQL, RPC, and other API patterns."""
        patterns = defaultdict(list)

        # Detect REST CRUD entities (entities with multiple HTTP methods)
        for entity_name, entity_data in self.graph["entities"].items():
            crud_ops = set(entity_data["crud"].keys())
            if len(crud_ops) >= 3 or (crud_ops & {"create", "update", "delete"}):
                patterns["rest_crud"].append({
                    "entity": entity_name,
                    "operations": sorted(crud_ops),
                    "endpoints": entity_data["endpoints"][:5],  # cap for readability
                })

        # Detect GraphQL
        for ep in self._raw_endpoints:
            path_lower = urlparse(ep["url"]).path.lower()
            if any(kw in path_lower for kw in ("/graphql", "/graphiql", "/playground", "/gql")):
                patterns["graphql"].append(ep["url"])

        # Detect RPC-style endpoints (verb-based paths)
        rpc_verbs = {'get', 'set', 'create', 'delete', 'update', 'list', 'fetch', 'send', 'execute', 'run', 'process', 'validate', 'check', 'search', 'find', 'submit', 'approve', 'reject', 'cancel'}
        for ep in self._raw_endpoints:
            segments = [s.lower() for s in urlparse(ep["url"]).path.split("/") if s]
            if segments:
                last_seg = segments[-1]
                # Check if the last segment starts with a verb (RPC style)
                for verb in rpc_verbs:
                    if last_seg.startswith(verb) and len(last_seg) > len(verb):
                        # camelCase or PascalCase after verb: createUser, deleteOrder
                        patterns["rpc_style"].append(ep["url"])
                        break

        # Detect versioned APIs
        for ep in self._raw_endpoints:
            path = urlparse(ep["url"]).path
            version_match = re.search(r'/v(\d+)/', path, re.I)
            if version_match:
                version = f"v{version_match.group(1)}"
                if version not in patterns.get("versioned_api", {}):
                    patterns["versioned_api"].append(ep["url"])

        # Deduplicate
        for key in patterns:
            if isinstance(patterns[key], list) and patterns[key] and isinstance(patterns[key][0], str):
                patterns[key] = sorted(set(patterns[key]))

        self.graph["api_patterns"] = dict(patterns)

    # ------------------------------------------------------------------
    # Attack path generation
    # ------------------------------------------------------------------

    def _build_attack_paths(self):
        """Generate high-value attack paths from the graph structure."""
        paths = []

        paths.extend(self._attack_admin_takeover())
        paths.extend(self._attack_idor_chains())
        paths.extend(self._attack_file_upload())
        paths.extend(self._attack_payment_abuse())
        paths.extend(self._attack_api_key_exposure())
        paths.extend(self._attack_privilege_escalation())
        paths.extend(self._attack_mass_assignment())

        self.graph["attack_paths"] = paths

    def _attack_admin_takeover(self) -> list:
        """Registration → Login → Admin endpoint access."""
        paths = []

        # Find admin endpoints
        admin_eps = []
        for ep in self._raw_endpoints:
            path_lower = urlparse(ep["url"]).path.lower()
            segments = {s.lower() for s in path_lower.split("/") if s}
            if segments & ADMIN_KEYWORDS:
                admin_eps.append(ep)

        if not admin_eps:
            return paths

        # Find registration and login endpoints
        reg_eps = [f["endpoints"] for f in self.graph["auth_flows"] if f["type"] == "registration"]
        login_eps = [f["endpoints"] for f in self.graph["auth_flows"] if f["type"] == "login"]

        reg_ep = reg_eps[0][0] if reg_eps and reg_eps[0] else None
        login_ep = login_eps[0][0] if login_eps and login_eps[0] else None

        steps = []
        if reg_ep:
            steps.append({"endpoint": reg_ep["url"], "method": reg_ep["method"], "action": "Register new account"})
        if login_ep:
            steps.append({"endpoint": login_ep["url"], "method": login_ep["method"], "action": "Authenticate and obtain token"})

        for aep in admin_eps[:3]:  # Limit to top 3 admin endpoints
            steps_copy = list(steps)
            steps_copy.append({
                "endpoint": aep["url"],
                "method": aep["method"],
                "action": "Access admin endpoint with regular user token",
            })
            paths.append({
                "name": "Admin Takeover — Broken Access Control",
                "risk": "critical",
                "description": "Register as regular user, then access admin functionality without proper authorization checks",
                "steps": steps_copy,
            })

        return paths

    def _attack_idor_chains(self) -> list:
        """Resource enumeration → Access other user's data via IDOR."""
        paths = []

        for entity_name, entity_data in self.graph["entities"].items():
            if not entity_data["has_id_access"]:
                continue
            if entity_name in SKIP_SEGMENTS:
                continue

            # Entities with ID-based access are IDOR candidates
            read_eps = entity_data["crud"].get("read", [])
            if not read_eps:
                continue

            steps = [
                {
                    "endpoint": read_eps[0],
                    "method": "GET",
                    "action": f"Access own {entity_name} resource to capture valid ID format",
                },
                {
                    "endpoint": read_eps[0],
                    "method": "GET",
                    "action": f"Enumerate {entity_name} IDs (increment/decrement) to access other users' data",
                },
            ]

            # If entity has update/delete, those are higher impact
            if "update" in entity_data["crud"]:
                steps.append({
                    "endpoint": entity_data["crud"]["update"][0],
                    "method": "PUT",
                    "action": f"Modify another user's {entity_name} data via IDOR",
                })
            if "delete" in entity_data["crud"]:
                steps.append({
                    "endpoint": entity_data["crud"]["delete"][0],
                    "method": "DELETE",
                    "action": f"Delete another user's {entity_name} via IDOR",
                })

            risk = "high"
            if entity_name in ("user", "account", "profile", "admin"):
                risk = "critical"
            elif entity_name in ("order", "payment", "transaction", "invoice", "wallet"):
                risk = "critical"

            paths.append({
                "name": f"IDOR — {entity_name.title()} Enumeration",
                "risk": risk,
                "description": f"Sequential ID access on /{entity_name} allows accessing other users' resources",
                "steps": steps,
            })

        return paths

    def _attack_file_upload(self) -> list:
        """Upload endpoint → File access → RCE via uploaded shell."""
        paths = []

        upload_eps = []
        file_access_eps = []

        for ep in self._raw_endpoints:
            path_lower = urlparse(ep["url"]).path.lower()
            segments = {s.lower() for s in path_lower.split("/") if s}

            if segments & UPLOAD_KEYWORDS and ep["method"] in ("POST", "PUT"):
                upload_eps.append(ep)
            elif segments & {"file", "files", "media", "uploads", "attachment", "attachments", "image", "images", "document", "documents", "download"}:
                if ep["method"] == "GET":
                    file_access_eps.append(ep)

        if not upload_eps:
            return paths

        for uep in upload_eps[:2]:
            steps = [
                {
                    "endpoint": uep["url"],
                    "method": uep["method"],
                    "action": "Upload malicious file (web shell, SVG with XSS, polyglot)",
                },
            ]
            if file_access_eps:
                steps.append({
                    "endpoint": file_access_eps[0]["url"],
                    "method": "GET",
                    "action": "Access uploaded file to trigger execution",
                })
            steps.append({
                "endpoint": uep["url"].rsplit("/", 1)[0] + "/shell.php",
                "method": "GET",
                "action": "Execute uploaded web shell for RCE",
            })

            paths.append({
                "name": "File Upload → RCE Chain",
                "risk": "critical",
                "description": "Upload a web shell or polyglot file, then access it to achieve remote code execution",
                "steps": steps,
            })

        return paths

    def _attack_payment_abuse(self) -> list:
        """Cart → Checkout → Payment manipulation."""
        paths = []

        payment_eps = []
        cart_eps = []
        checkout_eps = []

        for ep in self._raw_endpoints:
            path_lower = urlparse(ep["url"]).path.lower()
            segments = {s.lower() for s in path_lower.split("/") if s}

            if segments & {"cart", "basket"}:
                cart_eps.append(ep)
            elif segments & {"checkout", "pay", "charge"}:
                checkout_eps.append(ep)
            elif segments & PAYMENT_KEYWORDS:
                payment_eps.append(ep)

        all_payment = cart_eps + checkout_eps + payment_eps
        if len(all_payment) < 2:
            return paths

        steps = []
        if cart_eps:
            steps.append({
                "endpoint": cart_eps[0]["url"],
                "method": cart_eps[0]["method"],
                "action": "Add items to cart, note price parameters",
            })
        if checkout_eps:
            steps.append({
                "endpoint": checkout_eps[0]["url"],
                "method": checkout_eps[0]["method"],
                "action": "Intercept checkout request, modify price/quantity/discount parameters",
            })
        if payment_eps:
            steps.append({
                "endpoint": payment_eps[0]["url"],
                "method": payment_eps[0]["method"],
                "action": "Submit payment with manipulated amount (race condition, negative value, zero)",
            })

        if steps:
            paths.append({
                "name": "Payment Flow Manipulation",
                "risk": "critical",
                "description": "Manipulate price, quantity, or discount parameters in the payment flow",
                "steps": steps,
            })

        return paths

    def _attack_api_key_exposure(self) -> list:
        """Info disclosure endpoint → Use exposed credentials."""
        paths = []

        sensitive_eps = []
        for ep in self._raw_endpoints:
            path_lower = urlparse(ep["url"]).path.lower()
            segments = {s.lower() for s in path_lower.split("/") if s}

            if segments & SENSITIVE_KEYWORDS:
                sensitive_eps.append(ep)
            # Also catch common info disclosure paths
            elif any(kw in path_lower for kw in ('.env', '.git', 'debug', 'phpinfo', 'server-status', 'actuator', 'heapdump', 'swagger', 'api-docs')):
                sensitive_eps.append(ep)

        if not sensitive_eps:
            return paths

        for sep in sensitive_eps[:3]:
            paths.append({
                "name": "API Key / Secret Exposure",
                "risk": "high",
                "description": f"Sensitive endpoint may leak API keys, tokens, or internal configuration",
                "steps": [
                    {
                        "endpoint": sep["url"],
                        "method": sep["method"],
                        "action": "Access sensitive endpoint to extract secrets/configuration",
                    },
                    {
                        "endpoint": "(discovered API)",
                        "method": "GET",
                        "action": "Use extracted API key/token to access protected resources",
                    },
                ],
            })

        return paths

    def _attack_privilege_escalation(self) -> list:
        """User profile update → Set role/is_admin field (mass assignment)."""
        paths = []

        # Find user/account/profile entities with update capability
        for entity_name in ("user", "account", "profile"):
            entity = self.graph["entities"].get(entity_name)
            if not entity:
                continue

            update_eps = entity["crud"].get("update", [])
            if not update_eps:
                continue

            # Check if role-related params exist
            role_params = [p for p in entity["params"] if any(kw in p.lower() for kw in ("role", "admin", "permission", "privilege", "group", "level", "type"))]

            steps = [
                {
                    "endpoint": update_eps[0],
                    "method": "PUT",
                    "action": f"Update {entity_name} profile with added role/admin/permission fields",
                },
            ]

            desc = f"Modify {entity_name} update request to include privilege escalation fields"
            if role_params:
                desc += f" (detected params: {', '.join(role_params)})"
                risk = "critical"
            else:
                risk = "high"

            paths.append({
                "name": f"Privilege Escalation via {entity_name.title()} Update",
                "risk": risk,
                "description": desc,
                "steps": steps,
            })

        return paths

    def _attack_mass_assignment(self) -> list:
        """Detect entities with create/update that may accept extra fields."""
        paths = []

        for entity_name, entity_data in self.graph["entities"].items():
            if entity_name in ("user", "account", "profile"):
                continue  # Already covered by privilege escalation

            create_eps = entity_data["crud"].get("create", [])
            update_eps = entity_data["crud"].get("update", [])
            target_eps = create_eps + update_eps

            if not target_eps:
                continue

            # Only flag entities that have relationships (more complex = more risk)
            related = [r for r in self.graph["relationships"] if r["from"] == entity_name or r["to"] == entity_name]
            if not related:
                continue

            paths.append({
                "name": f"Mass Assignment — {entity_name.title()}",
                "risk": "medium",
                "description": f"Add unexpected fields to {entity_name} create/update to modify related data or internal fields",
                "steps": [
                    {
                        "endpoint": target_eps[0],
                        "method": "POST" if create_eps else "PUT",
                        "action": f"Send {entity_name} create/update with extra fields (price, status, owner_id, is_verified)",
                    },
                ],
            })

        return paths
