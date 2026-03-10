"""
ID Harvester — Collects identifiers from all API responses during scan.

Stores harvested IDs in scan context["harvested_ids"] as:
{
    "numeric": [1, 2, 3, 42, 100, ...],
    "uuid": ["a1b2c3d4-...", ...],
    "slug": ["admin", "user1", ...],
    "email": ["admin@site.com", ...],
    "by_endpoint": {
        "/api/orders": {"ids": [1,2,3], "id_field": "id"},
        "/api/users/1": {"ids": [1], "id_field": "path_param"},
    }
}
"""
import json
import re
import logging
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
NUMERIC_PATH_RE = re.compile(r'/(\d{1,10})(?:/|$|\?)')
UUID_PATH_RE = re.compile(r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)', re.I)
SLUG_PATH_RE = re.compile(r'/(?:api/(?:v\d+/)?)?[a-z_]+/([a-z][a-z0-9_\-]{1,30})(?:/|$|\?)')
RESOURCE_PATH_RE = re.compile(r'/(?:api/(?:v\d+/)?)?([a-z_]+)/(?:\d+|[0-9a-f\-]{36})')

ID_FIELD_NAMES = {
    "id", "Id", "ID", "_id",
    "uid", "uuid", "guid",
    "user_id", "userId", "userID", "user",
    "account_id", "accountId", "accountID",
    "order_id", "orderId", "orderID",
    "profile_id", "profileId", "profileID",
    "item_id", "itemId", "itemID",
    "product_id", "productId", "productID",
    "category_id", "categoryId", "categoryID",
    "transaction_id", "transactionId", "transactionID",
    "payment_id", "paymentId", "paymentID",
    "invoice_id", "invoiceId", "invoiceID",
    "session_id", "sessionId", "sessionID",
    "comment_id", "commentId", "commentID",
    "post_id", "postId", "postID",
    "article_id", "articleId", "articleID",
    "customer_id", "customerId", "customerID",
    "message_id", "messageId", "messageID",
    "ticket_id", "ticketId", "ticketID",
    "doc_id", "docId", "document_id", "documentId",
    "file_id", "fileId", "fileID",
    "report_id", "reportId", "reportID",
    "project_id", "projectId", "projectID",
    "team_id", "teamId", "teamID",
    "org_id", "orgId", "organization_id", "organizationId",
    "group_id", "groupId", "groupID",
    "role_id", "roleId", "roleID",
    "token", "api_key", "key",
}

SLUG_BLACKLIST = {
    "api", "v1", "v2", "v3", "v4", "graphql", "rest", "json", "xml",
    "html", "css", "js", "png", "jpg", "svg", "gif", "ico", "woff",
    "true", "false", "null", "undefined", "none",
}

MAX_NUMERIC_IDS = 10000
MAX_UUIDS = 5000
MAX_SLUGS = 2000
MAX_EMAILS = 1000


class IDHarvester:
    def __init__(self):
        self._numeric: set[int] = set()
        self._uuids: set[str] = set()
        self._slugs: set[str] = set()
        self._emails: set[str] = set()
        self._by_endpoint: dict[str, dict] = defaultdict(lambda: {"ids": [], "id_fields": set()})
        self._sequential_ranges: list[tuple[int, int]] = []
        self._response_signatures: dict[str, list[dict]] = defaultdict(list)

    def harvest_from_response(self, url: str, response_body: str, status_code: int) -> None:
        if status_code < 200 or status_code >= 400:
            return

        parsed = urlparse(url)
        path = parsed.path
        endpoint_key = self._normalize_endpoint(path)

        self._harvest_from_url(url, endpoint_key)

        if not response_body or not response_body.strip():
            return

        try:
            data = json.loads(response_body)
            self._harvest_from_json(data, endpoint_key)
        except (json.JSONDecodeError, ValueError):
            self._harvest_from_text(response_body, endpoint_key)

    def harvest_from_endpoints(self, endpoints: list[dict]) -> None:
        for ep in endpoints:
            url = ep.get("url") or ep.get("path", "")
            if not url:
                continue
            endpoint_key = self._normalize_endpoint(urlparse(url).path)
            self._harvest_from_url(url, endpoint_key)

            params = ep.get("params", {})
            if isinstance(params, dict):
                for key, val in params.items():
                    if self._is_id_field(key) and val:
                        self._classify_and_store(val, endpoint_key, key)

    def get_ids_for_bruteforce(self, endpoint_url: str, max_ids: int = 100) -> list:
        endpoint_key = self._normalize_endpoint(urlparse(endpoint_url).path)
        result = []
        seen = set()

        id_type = self._detect_id_type(endpoint_url)

        if id_type == "uuid":
            for uid in self._uuids:
                if len(result) >= max_ids:
                    break
                own_ids = {str(i) for i in self._by_endpoint[endpoint_key]["ids"]}
                if uid not in own_ids:
                    result.append(uid)
                    seen.add(uid)
            return result[:max_ids]

        cross_ids = []
        for ep, info in self._by_endpoint.items():
            if ep == endpoint_key:
                continue
            for i in info["ids"]:
                if isinstance(i, int) and i not in seen:
                    cross_ids.append(i)
                    seen.add(i)

        cross_ids.sort()
        result.extend(cross_ids[:max_ids // 2])

        remaining = max_ids - len(result)
        if remaining > 0:
            seq_start = 1
            seq_end = min(1001, seq_start + remaining)
            for i in range(seq_start, seq_end):
                if i not in seen:
                    result.append(i)
                    if len(result) >= max_ids:
                        break

        return result[:max_ids]

    def get_all_numeric_ids(self) -> list[int]:
        return sorted(self._numeric)

    def get_auth_context_endpoints(self) -> list[dict]:
        results = []
        for endpoint, sigs in self._response_signatures.items():
            if len(sigs) < 2:
                continue
            sizes = [s["size"] for s in sigs]
            if max(sizes) > min(sizes) * 1.5 and min(sizes) > 0:
                results.append({
                    "endpoint": endpoint,
                    "variations": len(sigs),
                    "size_range": [min(sizes), max(sizes)],
                    "ids_tested": [s["id"] for s in sigs],
                })
        return results

    def summary(self) -> dict:
        return {
            "total_numeric": len(self._numeric),
            "total_uuids": len(self._uuids),
            "total_slugs": len(self._slugs),
            "total_emails": len(self._emails),
            "endpoints_with_ids": len(self._by_endpoint),
            "sequential_ranges": self._sequential_ranges,
            "top_endpoints": sorted(
                [(k, len(v["ids"])) for k, v in self._by_endpoint.items()],
                key=lambda x: x[1],
                reverse=True,
            )[:10],
        }

    def to_dict(self) -> dict:
        return {
            "numeric": sorted(self._numeric)[:MAX_NUMERIC_IDS],
            "uuid": sorted(self._uuids)[:MAX_UUIDS],
            "slug": sorted(self._slugs)[:MAX_SLUGS],
            "email": sorted(self._emails)[:MAX_EMAILS],
            "by_endpoint": {
                k: {"ids": v["ids"][:500], "id_fields": list(v["id_fields"])}
                for k, v in self._by_endpoint.items()
            },
        }

    def record_response_signature(self, endpoint: str, id_value, response_body: str) -> None:
        self._response_signatures[endpoint].append({
            "id": id_value,
            "size": len(response_body) if response_body else 0,
        })

    def _harvest_from_url(self, url: str, endpoint_key: str) -> None:
        parsed = urlparse(url)
        path = parsed.path

        for match in NUMERIC_PATH_RE.finditer(path):
            val = int(match.group(1))
            if 0 < val < 10_000_000:
                self._add_numeric(val, endpoint_key, "path_param")

        for match in UUID_PATH_RE.finditer(path):
            self._add_uuid(match.group(1).lower(), endpoint_key, "path_param")

        qs = parse_qs(parsed.query)
        for key, values in qs.items():
            if self._is_id_field(key):
                for v in values:
                    self._classify_and_store(v, endpoint_key, key)

    def _harvest_from_json(self, data, endpoint_key: str, depth: int = 0) -> None:
        if depth > 10:
            return

        if isinstance(data, dict):
            for key, value in data.items():
                if self._is_id_field(key) and value is not None:
                    self._classify_and_store(value, endpoint_key, key)
                elif isinstance(value, (dict, list)):
                    self._harvest_from_json(value, endpoint_key, depth + 1)
                elif isinstance(value, str):
                    if UUID_RE.fullmatch(value):
                        self._add_uuid(value.lower(), endpoint_key, key)
                    elif EMAIL_RE.fullmatch(value) and self._is_email_field(key):
                        self._add_email(value, endpoint_key, key)

        elif isinstance(data, list):
            numeric_ids_in_list = []
            for item in data[:200]:
                if isinstance(item, dict):
                    self._harvest_from_json(item, endpoint_key, depth + 1)
                    if "id" in item and isinstance(item["id"], int):
                        numeric_ids_in_list.append(item["id"])
                elif isinstance(item, (int, float)) and isinstance(item, int):
                    if 0 < item < 10_000_000:
                        self._add_numeric(item, endpoint_key, "list_item")

            self._detect_sequential(numeric_ids_in_list, endpoint_key)

    def _harvest_from_text(self, text: str, endpoint_key: str) -> None:
        for match in UUID_RE.finditer(text):
            self._add_uuid(match.group(0).lower(), endpoint_key, "text_body")

        for match in EMAIL_RE.finditer(text):
            self._add_email(match.group(0), endpoint_key, "text_body")

    def _classify_and_store(self, value, endpoint_key: str, field_name: str) -> None:
        if isinstance(value, bool):
            return

        if isinstance(value, int):
            if 0 < value < 10_000_000:
                self._add_numeric(value, endpoint_key, field_name)
            return

        if isinstance(value, float):
            if value == int(value) and 0 < value < 10_000_000:
                self._add_numeric(int(value), endpoint_key, field_name)
            return

        if not isinstance(value, str) or not value.strip():
            return

        value = value.strip()

        if value.isdigit() and len(value) <= 10:
            num = int(value)
            if 0 < num < 10_000_000:
                self._add_numeric(num, endpoint_key, field_name)
        elif UUID_RE.fullmatch(value):
            self._add_uuid(value.lower(), endpoint_key, field_name)
        elif EMAIL_RE.fullmatch(value):
            self._add_email(value, endpoint_key, field_name)
        elif 1 < len(value) <= 40 and re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_\-\.]+', value):
            slug = value.lower()
            if slug not in SLUG_BLACKLIST:
                self._add_slug(slug, endpoint_key, field_name)

    def _add_numeric(self, val: int, endpoint_key: str, field_name: str) -> None:
        if len(self._numeric) < MAX_NUMERIC_IDS:
            self._numeric.add(val)
        self._by_endpoint[endpoint_key]["ids"].append(val)
        self._by_endpoint[endpoint_key]["id_fields"].add(field_name)

    def _add_uuid(self, val: str, endpoint_key: str, field_name: str) -> None:
        if len(self._uuids) < MAX_UUIDS:
            self._uuids.add(val)
        self._by_endpoint[endpoint_key]["ids"].append(val)
        self._by_endpoint[endpoint_key]["id_fields"].add(field_name)

    def _add_slug(self, val: str, endpoint_key: str, field_name: str) -> None:
        if len(self._slugs) < MAX_SLUGS:
            self._slugs.add(val)

    def _add_email(self, val: str, endpoint_key: str, field_name: str) -> None:
        if len(self._emails) < MAX_EMAILS:
            self._emails.add(val)

    def _detect_sequential(self, ids: list[int], endpoint_key: str) -> None:
        if len(ids) < 3:
            return
        sorted_ids = sorted(ids)
        seq_start = sorted_ids[0]
        seq_len = 1
        for i in range(1, len(sorted_ids)):
            if sorted_ids[i] == sorted_ids[i - 1] + 1:
                seq_len += 1
            else:
                if seq_len >= 3:
                    self._sequential_ranges.append((seq_start, sorted_ids[i - 1]))
                    logger.info(
                        "Sequential ID range detected at %s: %d-%d",
                        endpoint_key, seq_start, sorted_ids[i - 1],
                    )
                seq_start = sorted_ids[i]
                seq_len = 1
        if seq_len >= 3:
            self._sequential_ranges.append((seq_start, sorted_ids[-1]))

    def _detect_id_type(self, url: str) -> str:
        path = urlparse(url).path
        if UUID_PATH_RE.search(path):
            return "uuid"
        if NUMERIC_PATH_RE.search(path):
            return "numeric"
        return "numeric"

    @staticmethod
    def _normalize_endpoint(path: str) -> str:
        path = re.sub(r'/\d+', '/{id}', path)
        path = re.sub(
            r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '/{uuid}',
            path,
            flags=re.I,
        )
        return path.rstrip('/')

    @staticmethod
    def _is_id_field(name: str) -> bool:
        if name in ID_FIELD_NAMES:
            return True
        lower = name.lower()
        return lower.endswith(("_id", "id")) and len(lower) <= 30

    @staticmethod
    def _is_email_field(name: str) -> bool:
        lower = name.lower()
        return any(k in lower for k in ("email", "mail", "contact", "owner", "author", "creator"))
