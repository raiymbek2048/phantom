"""
Adversarial Self-Testing — Red vs Blue AI combat for payload/detection improvement.

RED team generates evasive payloads via LLM.
BLUE team tries to detect them via pattern matching + LLM WAF simulation.
Results are stored as KnowledgePattern records for continuous learning.
"""
import asyncio
import logging
import re
import uuid
from datetime import datetime

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.llm_engine import LLMEngine, LLMError
from app.models.knowledge import KnowledgePattern

logger = logging.getLogger(__name__)

# BLUE team detection patterns per vuln type
DETECTION_PATTERNS: dict[str, list[re.Pattern]] = {
    "xss": [
        re.compile(r"<script", re.IGNORECASE),
        re.compile(r"onerror\s*=", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"on\w+\s*=", re.IGNORECASE),
        re.compile(r"<svg", re.IGNORECASE),
        re.compile(r"<img[^>]+on\w+", re.IGNORECASE),
        re.compile(r"<iframe", re.IGNORECASE),
        re.compile(r"alert\s*\(", re.IGNORECASE),
        re.compile(r"document\.(cookie|domain|location)", re.IGNORECASE),
        re.compile(r"eval\s*\(", re.IGNORECASE),
    ],
    "sqli": [
        re.compile(r"\bUNION\b", re.IGNORECASE),
        re.compile(r"\bSELECT\b", re.IGNORECASE),
        re.compile(r"\bDROP\b", re.IGNORECASE),
        re.compile(r"--\s*$", re.IGNORECASE),
        re.compile(r"'\s*OR\b", re.IGNORECASE),
        re.compile(r"1\s*=\s*1", re.IGNORECASE),
        re.compile(r"SLEEP\s*\(", re.IGNORECASE),
        re.compile(r"BENCHMARK\s*\(", re.IGNORECASE),
        re.compile(r"WAITFOR\s+DELAY", re.IGNORECASE),
        re.compile(r"'\s*;\s*", re.IGNORECASE),
    ],
    "cmd_injection": [
        re.compile(r";\s+"),
        re.compile(r"\|\s+"),
        re.compile(r"`"),
        re.compile(r"\$\("),
        re.compile(r"/etc/passwd"),
        re.compile(r"&&\s+"),
        re.compile(r"\bcat\b"),
        re.compile(r"\bwhoami\b", re.IGNORECASE),
        re.compile(r"\bcurl\b", re.IGNORECASE),
        re.compile(r"\bwget\b", re.IGNORECASE),
    ],
    "ssrf": [
        re.compile(r"127\.0\.0\.1"),
        re.compile(r"\blocalhost\b", re.IGNORECASE),
        re.compile(r"0x7f", re.IGNORECASE),
        re.compile(r"169\.254\.169\.254"),
        re.compile(r"\[::1\]"),
        re.compile(r"0177\.0\.0\.1"),
        re.compile(r"file://", re.IGNORECASE),
        re.compile(r"gopher://", re.IGNORECASE),
        re.compile(r"dict://", re.IGNORECASE),
        re.compile(r"2130706433"),
    ],
    "lfi": [
        re.compile(r"\.\./"),
        re.compile(r"\.\.\\\\"),
        re.compile(r"/etc/"),
        re.compile(r"php://", re.IGNORECASE),
        re.compile(r"file://", re.IGNORECASE),
        re.compile(r"%2e%2e", re.IGNORECASE),
        re.compile(r"%252e", re.IGNORECASE),
        re.compile(r"\.\.%c0%af", re.IGNORECASE),
        re.compile(r"/proc/self", re.IGNORECASE),
        re.compile(r"win\.ini", re.IGNORECASE),
    ],
}

# Default vuln types to test
DEFAULT_VULN_TYPES = ["xss", "sqli", "cmd_injection", "ssrf", "lfi"]


class AdversarialTester:
    """Red vs Blue adversarial testing engine."""

    def __init__(self):
        self.llm = LLMEngine()

    async def close(self):
        await self.llm.close()

    # ------------------------------------------------------------------
    # 1. Main adversarial loop
    # ------------------------------------------------------------------

    async def run_red_vs_blue(
        self,
        db: AsyncSession,
        vuln_type: str | None = None,
        rounds: int = 10,
    ) -> dict:
        """
        Run adversarial Red vs Blue rounds.

        Args:
            db: Database session
            vuln_type: Specific vuln type to test, or None for all
            rounds: Number of rounds per vuln type
        """
        vuln_types = [vuln_type] if vuln_type else DEFAULT_VULN_TYPES
        total_red_wins = 0
        total_blue_wins = 0
        total_rounds = 0
        new_payloads: list[dict] = []
        new_signatures: list[dict] = []

        for vt in vuln_types:
            logger.info(f"Adversarial: starting {rounds} rounds for {vt}")
            for round_num in range(1, rounds + 1):
                total_rounds += 1
                try:
                    result = await self._play_round(db, vt, round_num)
                except Exception as e:
                    logger.error(f"Round {round_num} ({vt}) error: {e}")
                    continue

                if result["red_wins"]:
                    total_red_wins += 1
                    new_payloads.append({
                        "vuln_type": vt,
                        "payload": result["payload"],
                        "technique": result.get("technique", ""),
                        "evasion_method": result.get("evasion_method", ""),
                    })
                else:
                    total_blue_wins += 1
                    new_signatures.append({
                        "vuln_type": vt,
                        "detection_method": result.get("detection_method", ""),
                        "detection_rule": result.get("detection_rule", ""),
                    })

                # 1-second sleep between rounds to avoid rate limiting
                if round_num < rounds or vt != vuln_types[-1]:
                    await asyncio.sleep(1)

        # Store overall adversarial session result
        session_record = KnowledgePattern(
            id=str(uuid.uuid4()),
            pattern_type="adversarial_result",
            pattern_data={
                "rounds_played": total_rounds,
                "red_wins": total_red_wins,
                "blue_wins": total_blue_wins,
                "survival_rate": round(total_red_wins / max(total_rounds, 1), 3),
                "vuln_types_tested": vuln_types,
                "new_payloads_count": len(new_payloads),
                "new_signatures_count": len(new_signatures),
                "timestamp": datetime.utcnow().isoformat() + "Z",
            },
            confidence=0.8,
            sample_count=total_rounds,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(session_record)
        await db.commit()

        return {
            "rounds_played": total_rounds,
            "red_wins": total_red_wins,
            "blue_wins": total_blue_wins,
            "new_payloads": new_payloads,
            "new_signatures": new_signatures,
            "survival_rate": round(total_red_wins / max(total_rounds, 1), 3),
        }

    async def _play_round(self, db: AsyncSession, vuln_type: str, round_num: int) -> dict:
        """Play a single Red vs Blue round."""

        # --- RED TEAM: generate evasive payload ---
        red_prompt = (
            f"Generate a {vuln_type} payload that would bypass common WAF rules and security filters. "
            f"Make it creative and evasive. Use encoding, obfuscation, or novel techniques. "
            f"Return JSON: {{\"payload\": \"<the payload>\", \"technique\": \"<technique name>\", "
            f"\"evasion_method\": \"<how it evades detection>\"}}"
        )
        try:
            red_result = await self.llm.analyze_json(red_prompt)
        except LLMError:
            # Fallback: use a basic payload
            red_result = {
                "payload": f"<img src=x onerror=alert(1)>" if vuln_type == "xss" else "' OR 1=1--",
                "technique": "fallback",
                "evasion_method": "none",
            }

        payload = red_result.get("payload", "")
        technique = red_result.get("technique", "unknown")
        evasion_method = red_result.get("evasion_method", "unknown")

        if not payload:
            return {"red_wins": False, "detection_method": "empty_payload", "payload": ""}

        # --- BLUE TEAM PHASE 1: pattern matching ---
        pattern_detected = False
        detection_method = ""
        patterns = DETECTION_PATTERNS.get(vuln_type, [])
        for pat in patterns:
            if pat.search(payload):
                pattern_detected = True
                detection_method = f"regex:{pat.pattern}"
                break

        # --- BLUE TEAM PHASE 2: LLM WAF simulation ---
        llm_blocked = False
        llm_detection_rule = ""
        if not pattern_detected:
            # Only call LLM if pattern matching didn't catch it
            blue_prompt = (
                f"You are a Web Application Firewall (WAF). Analyze this HTTP request payload and decide "
                f"if it should be blocked. The payload might be attempting a {vuln_type} attack.\n\n"
                f"Payload: {payload}\n\n"
                f"Respond with JSON: {{\"blocked\": true/false, \"reason\": \"<why>\", "
                f"\"detection_rule\": \"<what rule would catch this>\"}}"
            )
            try:
                blue_result = await self.llm.analyze_json(blue_prompt)
                llm_blocked = bool(blue_result.get("blocked", False))
                llm_detection_rule = blue_result.get("detection_rule", "")
                if llm_blocked:
                    detection_method = f"llm_waf:{blue_result.get('reason', 'blocked')}"
            except LLMError:
                # If LLM fails, count it as not blocked
                pass

        # --- SCORING ---
        blue_wins = pattern_detected or llm_blocked
        red_wins = not blue_wins

        # --- LEARNING ---
        if red_wins:
            # Store evasive payload as effective_payload
            record = KnowledgePattern(
                id=str(uuid.uuid4()),
                pattern_type="effective_payload",
                vuln_type=vuln_type,
                pattern_data={
                    "payload": payload,
                    "technique": technique,
                    "evasion_method": evasion_method,
                    "source": "adversarial_red",
                    "round": round_num,
                },
                confidence=0.85,
                sample_count=1,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.add(record)
            await db.flush()
            logger.info(f"RED wins round {round_num} ({vuln_type}): payload evaded detection")
        else:
            # Store detection signature
            record = KnowledgePattern(
                id=str(uuid.uuid4()),
                pattern_type="detection_signature",
                vuln_type=vuln_type,
                pattern_data={
                    "payload_caught": payload,
                    "detection_method": detection_method,
                    "detection_rule": llm_detection_rule,
                    "source": "adversarial_blue",
                    "round": round_num,
                },
                confidence=0.8,
                sample_count=1,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.add(record)
            await db.flush()
            logger.info(f"BLUE wins round {round_num} ({vuln_type}): detected via {detection_method}")

        await db.commit()

        return {
            "red_wins": red_wins,
            "payload": payload,
            "technique": technique,
            "evasion_method": evasion_method,
            "detection_method": detection_method,
            "detection_rule": llm_detection_rule,
        }

    # ------------------------------------------------------------------
    # 2. Test a single payload's stealth
    # ------------------------------------------------------------------

    async def test_payload_stealth(
        self,
        payload: str,
        vuln_type: str,
        db: AsyncSession,
    ) -> dict:
        """
        Test how stealthy a single payload is against BLUE detection.

        Returns:
            {detected: bool, detection_method: str, evasion_score: 0-100}
        """
        if not payload:
            return {"detected": True, "detection_method": "empty_payload", "evasion_score": 0}

        detections: list[str] = []

        # Check regex patterns
        patterns = DETECTION_PATTERNS.get(vuln_type, [])
        for pat in patterns:
            if pat.search(payload):
                detections.append(f"regex:{pat.pattern}")

        # If no regex hit, check with LLM
        if not detections:
            try:
                blue_prompt = (
                    f"You are a WAF. Would you block this request? "
                    f"Payload: {payload}\n"
                    f"Respond JSON: {{\"blocked\": true/false, \"reason\": \"...\", "
                    f"\"detection_rule\": \"...\"}}"
                )
                result = await self.llm.analyze_json(blue_prompt)
                if result.get("blocked"):
                    detections.append(f"llm_waf:{result.get('reason', 'blocked')}")
            except LLMError:
                pass

        detected = len(detections) > 0
        # Evasion score: 100 = fully evasive, 0 = caught by everything
        total_checks = len(patterns) + 1  # patterns + LLM
        caught_count = len(detections)
        evasion_score = round((1 - caught_count / max(total_checks, 1)) * 100)

        return {
            "detected": detected,
            "detection_method": detections[0] if detections else "none",
            "all_detections": detections,
            "evasion_score": max(evasion_score, 0),
        }

    # ------------------------------------------------------------------
    # 3. Adversarial stats
    # ------------------------------------------------------------------

    async def get_adversarial_stats(self, db: AsyncSession) -> dict:
        """Get overall adversarial testing statistics."""

        # Total adversarial sessions
        sessions_result = await db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == "adversarial_result"
            ).order_by(KnowledgePattern.created_at.desc())
        )
        sessions = sessions_result.scalars().all()

        total_rounds = 0
        total_red_wins = 0
        total_blue_wins = 0
        for s in sessions:
            data = s.pattern_data or {}
            total_rounds += data.get("rounds_played", 0)
            total_red_wins += data.get("red_wins", 0)
            total_blue_wins += data.get("blue_wins", 0)

        # Win rates per vuln_type from effective_payload (RED wins)
        red_by_type = await db.execute(
            select(
                KnowledgePattern.vuln_type,
                func.count(KnowledgePattern.id),
            ).where(
                KnowledgePattern.pattern_type == "effective_payload",
                KnowledgePattern.pattern_data["source"].as_string() == "adversarial_red",
            ).group_by(KnowledgePattern.vuln_type)
        )
        red_wins_by_type = {vt: cnt for vt, cnt in red_by_type.all() if vt}

        # Blue wins per vuln_type
        blue_by_type = await db.execute(
            select(
                KnowledgePattern.vuln_type,
                func.count(KnowledgePattern.id),
            ).where(
                KnowledgePattern.pattern_type == "detection_signature",
                KnowledgePattern.pattern_data["source"].as_string() == "adversarial_blue",
            ).group_by(KnowledgePattern.vuln_type)
        )
        blue_wins_by_type = {vt: cnt for vt, cnt in blue_by_type.all() if vt}

        # Compute win rates
        all_types = set(list(red_wins_by_type.keys()) + list(blue_wins_by_type.keys()))
        win_rates: dict[str, dict] = {}
        for vt in all_types:
            r_wins = red_wins_by_type.get(vt, 0)
            b_wins = blue_wins_by_type.get(vt, 0)
            vt_total = r_wins + b_wins
            win_rates[vt] = {
                "red_wins": r_wins,
                "blue_wins": b_wins,
                "total": vt_total,
                "red_rate": round(r_wins / max(vt_total, 1), 3),
                "blue_rate": round(b_wins / max(vt_total, 1), 3),
            }

        # Most evasive techniques (top payloads that evaded detection)
        evasive_result = await db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == "effective_payload",
                KnowledgePattern.pattern_data["source"].as_string() == "adversarial_red",
            ).order_by(KnowledgePattern.confidence.desc()).limit(10)
        )
        evasive_payloads = evasive_result.scalars().all()
        most_evasive = [
            {
                "vuln_type": p.vuln_type,
                "technique": p.pattern_data.get("technique", ""),
                "evasion_method": p.pattern_data.get("evasion_method", ""),
                "payload_preview": p.pattern_data.get("payload", "")[:80],
            }
            for p in evasive_payloads
        ]

        # Most effective detection rules
        detection_result = await db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == "detection_signature",
                KnowledgePattern.pattern_data["source"].as_string() == "adversarial_blue",
            ).order_by(KnowledgePattern.created_at.desc()).limit(10)
        )
        detection_records = detection_result.scalars().all()
        effective_rules = [
            {
                "vuln_type": d.vuln_type,
                "detection_method": d.pattern_data.get("detection_method", ""),
                "detection_rule": d.pattern_data.get("detection_rule", ""),
            }
            for d in detection_records
        ]

        # Recent sessions
        recent = [
            {
                "id": s.id,
                "date": s.created_at.isoformat() + "Z" if s.created_at else None,
                "rounds": s.pattern_data.get("rounds_played", 0),
                "red_wins": s.pattern_data.get("red_wins", 0),
                "blue_wins": s.pattern_data.get("blue_wins", 0),
                "survival_rate": s.pattern_data.get("survival_rate", 0),
            }
            for s in sessions[:10]
        ]

        return {
            "total_sessions": len(sessions),
            "total_rounds": total_rounds,
            "total_red_wins": total_red_wins,
            "total_blue_wins": total_blue_wins,
            "overall_survival_rate": round(total_red_wins / max(total_rounds, 1), 3),
            "win_rates_by_type": win_rates,
            "most_evasive_techniques": most_evasive,
            "most_effective_rules": effective_rules,
            "recent_sessions": recent,
        }
