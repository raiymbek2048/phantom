"""
AI Mutation Engine — Dynamic Payload Generation

Uses Claude/Ollama to generate new payload variants by:
1. Mutating existing effective payloads from the knowledge base
2. Generating context-specific payloads for technology+vuln combos
3. Evolving payloads that successfully exploited real targets

All generated payloads are stored in KnowledgePattern with pattern_type="ai_mutation".
"""
import asyncio
import hashlib
import logging
import uuid
from collections import defaultdict
from datetime import datetime

from sqlalchemy import select, and_, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.llm_engine import LLMEngine, LLMError
from app.models.knowledge import KnowledgePattern
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


def _payload_hash(payload: str) -> str:
    """MD5 hash of payload text for deduplication."""
    return hashlib.md5(payload.strip().encode()).hexdigest()


async def generate_ai_mutations(db: AsyncSession, max_mutations: int = 50) -> dict:
    """
    Load existing effective payloads from knowledge base,
    group by vuln_type, and ask AI to generate creative mutations.

    Returns stats dict with mutations_generated, errors, llm_provider.
    """
    engine = LLMEngine()
    stats = {
        "mutations_generated": 0,
        "errors": [],
        "llm_provider": "none",
        "vuln_types_processed": 0,
    }

    try:
        if not await engine.is_available():
            stats["errors"].append("No LLM provider available")
            return stats

        stats["llm_provider"] = engine.provider

        # Load effective payloads grouped by vuln_type
        result = await db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == "effective_payload"
            ).order_by(KnowledgePattern.confidence.desc())
        )
        patterns = result.scalars().all()

        if not patterns:
            stats["errors"].append("No effective payloads found in knowledge base")
            return stats

        # Group by vuln_type, take top 3 per type
        by_vuln_type: dict[str, list[str]] = defaultdict(list)
        for p in patterns:
            vt = p.vuln_type or "unknown"
            if len(by_vuln_type[vt]) < 3:
                payload = p.pattern_data.get("payload", "") if isinstance(p.pattern_data, dict) else ""
                if payload:
                    by_vuln_type[vt].append(payload)

        if not by_vuln_type:
            stats["errors"].append("No payloads extracted from knowledge patterns")
            return stats

        # Load existing ai_mutation hashes for dedup
        existing_result = await db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == "ai_mutation"
            )
        )
        existing_mutations = existing_result.scalars().all()
        existing_hashes = set()
        for m in existing_mutations:
            key = m.pattern_data.get("key", "") if isinstance(m.pattern_data, dict) else ""
            if key:
                existing_hashes.add(key)

        total_generated = 0

        for vuln_type, payloads in by_vuln_type.items():
            if total_generated >= max_mutations:
                break

            payloads_text = "\n".join(f"  {i+1}. {p}" for i, p in enumerate(payloads))

            prompt = f"""You are an expert penetration tester. Given these existing payloads for {vuln_type}, generate 5 NEW creative mutations that would bypass common WAFs and security filters.

Existing payloads:
{payloads_text}

For each mutation, provide:
1. The mutated payload
2. The mutation technique used
3. Which WAFs this might bypass
4. Confidence level (0-1)

Return JSON array: [{{"payload": "...", "technique": "...", "bypasses": ["cloudflare"], "confidence": 0.7}}]"""

            try:
                mutations = await engine.analyze_json(prompt)

                if not isinstance(mutations, list):
                    mutations = [mutations] if isinstance(mutations, dict) else []

                for mut in mutations:
                    if total_generated >= max_mutations:
                        break

                    if not isinstance(mut, dict) or "payload" not in mut:
                        continue

                    payload = str(mut["payload"]).strip()
                    if not payload:
                        continue

                    p_hash = _payload_hash(payload)
                    if p_hash in existing_hashes:
                        continue

                    existing_hashes.add(p_hash)

                    pattern = KnowledgePattern(
                        id=str(uuid.uuid4()),
                        pattern_type="ai_mutation",
                        technology=None,
                        vuln_type=vuln_type,
                        pattern_data={
                            "original_type": vuln_type,
                            "payload": payload,
                            "technique": mut.get("technique", "unknown"),
                            "bypasses": mut.get("bypasses", []),
                            "generated_by": engine.provider,
                            "generated_at": datetime.utcnow().isoformat(),
                            "key": p_hash,
                        },
                        confidence=min(max(float(mut.get("confidence", 0.5)), 0.0), 1.0),
                        sample_count=0,
                    )
                    db.add(pattern)
                    total_generated += 1

                stats["vuln_types_processed"] += 1

                # Rate limiting between LLM calls
                await asyncio.sleep(1)

            except LLMError as e:
                stats["errors"].append(f"LLM error for {vuln_type}: {str(e)}")
                logger.warning(f"AI mutation failed for {vuln_type}: {e}")
            except Exception as e:
                stats["errors"].append(f"Error for {vuln_type}: {str(e)}")
                logger.error(f"Unexpected error mutating {vuln_type}: {e}", exc_info=True)

        await db.commit()
        stats["mutations_generated"] = total_generated

    except Exception as e:
        stats["errors"].append(f"Fatal error: {str(e)}")
        logger.error(f"AI mutation engine fatal error: {e}", exc_info=True)
    finally:
        await engine.close()

    return stats


async def generate_targeted_payloads(
    db: AsyncSession,
    technology: str,
    vuln_type: str,
    count: int = 10,
) -> dict:
    """
    Generate payloads specifically for a technology + vuln_type combo.

    Returns dict with payloads list and stats.
    """
    engine = LLMEngine()
    result_data = {
        "payloads": [],
        "technology": technology,
        "vuln_type": vuln_type,
        "count_requested": count,
        "count_generated": 0,
        "llm_provider": "none",
        "errors": [],
    }

    try:
        if not await engine.is_available():
            result_data["errors"].append("No LLM provider available")
            return result_data

        result_data["llm_provider"] = engine.provider

        prompt = f"""You are a senior penetration tester specializing in {technology} applications.
Generate {count} unique {vuln_type} payloads specifically designed for {technology}.

Consider:
- Common {technology} input handling patterns
- Known {technology} WAF/filter implementations
- Framework-specific encoding behaviors
- Real-world bypass techniques from bug bounty reports

Return JSON array: [{{"payload": "...", "context": "...", "technique": "...", "confidence": 0.8}}]"""

        mutations = await engine.analyze_json(prompt)

        if not isinstance(mutations, list):
            mutations = [mutations] if isinstance(mutations, dict) else []

        # Load existing hashes for dedup
        existing_result = await db.execute(
            select(KnowledgePattern).where(
                and_(
                    KnowledgePattern.pattern_type == "ai_mutation",
                    KnowledgePattern.vuln_type == vuln_type,
                    KnowledgePattern.technology == technology,
                )
            )
        )
        existing = existing_result.scalars().all()
        existing_hashes = set()
        for m in existing:
            key = m.pattern_data.get("key", "") if isinstance(m.pattern_data, dict) else ""
            if key:
                existing_hashes.add(key)

        generated = []
        for mut in mutations:
            if not isinstance(mut, dict) or "payload" not in mut:
                continue

            payload = str(mut["payload"]).strip()
            if not payload:
                continue

            p_hash = _payload_hash(payload)
            if p_hash in existing_hashes:
                continue

            existing_hashes.add(p_hash)

            pattern = KnowledgePattern(
                id=str(uuid.uuid4()),
                pattern_type="ai_mutation",
                technology=technology,
                vuln_type=vuln_type,
                pattern_data={
                    "original_type": vuln_type,
                    "payload": payload,
                    "technique": mut.get("technique", "unknown"),
                    "context": mut.get("context", ""),
                    "bypasses": mut.get("bypasses", []),
                    "generated_by": engine.provider,
                    "generated_at": datetime.utcnow().isoformat(),
                    "key": p_hash,
                },
                confidence=min(max(float(mut.get("confidence", 0.5)), 0.0), 1.0),
                sample_count=0,
            )
            db.add(pattern)
            generated.append({
                "payload": payload,
                "technique": mut.get("technique", "unknown"),
                "context": mut.get("context", ""),
                "confidence": pattern.confidence,
            })

        await db.commit()
        result_data["payloads"] = generated
        result_data["count_generated"] = len(generated)

    except LLMError as e:
        result_data["errors"].append(f"LLM error: {str(e)}")
        logger.warning(f"Targeted payload generation failed: {e}")
    except Exception as e:
        result_data["errors"].append(f"Error: {str(e)}")
        logger.error(f"Targeted payload generation error: {e}", exc_info=True)
    finally:
        await engine.close()

    return result_data


async def evolve_successful_payloads(db: AsyncSession) -> dict:
    """
    Find payloads that actually worked (from Vulnerability records),
    then ask AI to create evolved variants that are harder to detect.

    Returns stats dict with evolved count and errors.
    """
    engine = LLMEngine()
    stats = {
        "evolved": 0,
        "vuln_types_processed": 0,
        "errors": [],
        "llm_provider": "none",
    }

    try:
        if not await engine.is_available():
            stats["errors"].append("No LLM provider available")
            return stats

        stats["llm_provider"] = engine.provider

        # Query vulnerabilities with successful payloads
        result = await db.execute(
            select(Vulnerability).where(
                Vulnerability.payload_used.isnot(None),
                Vulnerability.payload_used != "",
            ).order_by(Vulnerability.created_at.desc()).limit(100)
        )
        vulns = result.scalars().all()

        if not vulns:
            stats["errors"].append("No vulnerabilities with successful payloads found")
            return stats

        # Group by vuln_type
        by_vuln_type: dict[str, list[str]] = defaultdict(list)
        for v in vulns:
            vt = v.vuln_type.value if hasattr(v.vuln_type, "value") else str(v.vuln_type)
            payload = v.payload_used.strip()
            if payload and payload not in by_vuln_type[vt]:
                by_vuln_type[vt].append(payload)

        # Load existing ai_mutation hashes for dedup
        existing_result = await db.execute(
            select(KnowledgePattern).where(
                KnowledgePattern.pattern_type == "ai_mutation"
            )
        )
        existing_mutations = existing_result.scalars().all()
        existing_hashes = set()
        for m in existing_mutations:
            key = m.pattern_data.get("key", "") if isinstance(m.pattern_data, dict) else ""
            if key:
                existing_hashes.add(key)

        for vuln_type, payloads in by_vuln_type.items():
            # Take up to 5 successful payloads per type
            sample = payloads[:5]
            payloads_text = "\n".join(f"  {i+1}. {p}" for i, p in enumerate(sample))

            prompt = f"""You are an expert penetration tester. These {vuln_type} payloads successfully exploited real targets:

{payloads_text}

Create 5 evolved variants that are harder to detect by WAFs and security filters.
Each variant should use a different evasion technique (encoding, case manipulation, comment injection, unicode, etc.)

Return JSON array: [{{"payload": "...", "technique": "...", "bypasses": ["cloudflare", "modsecurity"], "confidence": 0.8}}]"""

            try:
                mutations = await engine.analyze_json(prompt)

                if not isinstance(mutations, list):
                    mutations = [mutations] if isinstance(mutations, dict) else []

                for mut in mutations:
                    if not isinstance(mut, dict) or "payload" not in mut:
                        continue

                    payload = str(mut["payload"]).strip()
                    if not payload:
                        continue

                    p_hash = _payload_hash(payload)
                    if p_hash in existing_hashes:
                        continue

                    existing_hashes.add(p_hash)

                    # Evolved payloads get higher confidence since they derive from proven ones
                    base_confidence = float(mut.get("confidence", 0.7))
                    boosted_confidence = min(base_confidence + 0.1, 1.0)

                    pattern = KnowledgePattern(
                        id=str(uuid.uuid4()),
                        pattern_type="ai_mutation",
                        technology=None,
                        vuln_type=vuln_type,
                        pattern_data={
                            "original_type": vuln_type,
                            "payload": payload,
                            "technique": mut.get("technique", "evolution"),
                            "bypasses": mut.get("bypasses", []),
                            "evolved_from": "successful_exploit",
                            "generated_by": engine.provider,
                            "generated_at": datetime.utcnow().isoformat(),
                            "key": p_hash,
                        },
                        confidence=boosted_confidence,
                        sample_count=0,
                    )
                    db.add(pattern)
                    stats["evolved"] += 1

                stats["vuln_types_processed"] += 1

                # Rate limiting between LLM calls
                await asyncio.sleep(1)

            except LLMError as e:
                stats["errors"].append(f"LLM error for {vuln_type}: {str(e)}")
                logger.warning(f"Evolution failed for {vuln_type}: {e}")
            except Exception as e:
                stats["errors"].append(f"Error for {vuln_type}: {str(e)}")
                logger.error(f"Unexpected error evolving {vuln_type}: {e}", exc_info=True)

        await db.commit()

    except Exception as e:
        stats["errors"].append(f"Fatal error: {str(e)}")
        logger.error(f"Evolve engine fatal error: {e}", exc_info=True)
    finally:
        await engine.close()

    return stats


async def run_ai_mutation_engine(db: AsyncSession) -> dict:
    """
    Master function: runs generate_ai_mutations + evolve_successful_payloads.

    Returns combined stats.
    """
    logger.info("Starting AI Mutation Engine...")

    mutation_stats = await generate_ai_mutations(db)
    evolve_stats = await evolve_successful_payloads(db)

    combined = {
        "mutations_generated": mutation_stats.get("mutations_generated", 0),
        "evolved": evolve_stats.get("evolved", 0),
        "errors": mutation_stats.get("errors", []) + evolve_stats.get("errors", []),
        "llm_provider": mutation_stats.get("llm_provider", "none"),
        "vuln_types_mutated": mutation_stats.get("vuln_types_processed", 0),
        "vuln_types_evolved": evolve_stats.get("vuln_types_processed", 0),
    }

    logger.info(
        f"AI Mutation Engine complete: {combined['mutations_generated']} mutations, "
        f"{combined['evolved']} evolved, {len(combined['errors'])} errors"
    )

    return combined
