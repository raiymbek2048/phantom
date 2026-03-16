"""
Knowledge Graph — PostgreSQL-based graph for cross-target learning.

Builds a web of relationships between technologies, vulnerabilities, payloads,
WAFs, domains, and techniques discovered across all scans. Enables multi-hop
traversal queries to find attack strategies that worked on similar targets.

Nodes: technology, vulnerability, domain, endpoint, service, waf, credential, technique
Edges: runs_on, vulnerable_to, bypasses, discovered_at, effective_against,
       co_occurs_with, exploited_by
"""
import logging
from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy import select, func, and_, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.models.knowledge import KnowledgeNode, KnowledgeEdge
from app.models.vulnerability import Vulnerability, VulnType
from app.models.scan import Scan, ScanStatus
from app.models.target import Target

logger = logging.getLogger(__name__)

# Weight cap to prevent runaway edge weights
MAX_EDGE_WEIGHT = 5.0
WEIGHT_INCREMENT = 0.1


class KnowledgeGraph:
    """Graph-based knowledge queries for cross-target learning."""

    # ---- Core Graph Operations ----

    @staticmethod
    async def upsert_node(
        db: AsyncSession, node_type: str, name: str, properties: dict | None = None,
    ) -> str:
        """Find-or-create a node by (node_type, name). Returns node ID."""
        name_lower = name.lower().strip()
        if not name_lower:
            raise ValueError("Node name cannot be empty")

        result = await db.execute(
            select(KnowledgeNode).where(
                and_(
                    KnowledgeNode.node_type == node_type,
                    KnowledgeNode.name == name_lower,
                )
            )
        )
        node = result.scalar_one_or_none()

        if node:
            node.last_seen = datetime.utcnow()
            node.scan_count += 1
            if properties:
                merged = {**(node.properties or {}), **properties}
                node.properties = merged
            return node.id

        node = KnowledgeNode(
            node_type=node_type,
            name=name_lower,
            properties=properties or {},
        )
        db.add(node)
        await db.flush()
        return node.id

    @staticmethod
    async def add_edge(
        db: AsyncSession,
        source_id: str,
        target_id: str,
        edge_type: str,
        weight: float = 1.0,
        properties: dict | None = None,
    ) -> str:
        """Add or strengthen an edge. If it exists, increment weight (capped)."""
        result = await db.execute(
            select(KnowledgeEdge).where(
                and_(
                    KnowledgeEdge.source_id == source_id,
                    KnowledgeEdge.target_id == target_id,
                    KnowledgeEdge.edge_type == edge_type,
                )
            )
        )
        edge = result.scalar_one_or_none()

        if edge:
            edge.weight = min(MAX_EDGE_WEIGHT, edge.weight + WEIGHT_INCREMENT)
            edge.updated_at = datetime.utcnow()
            if properties:
                merged = {**(edge.properties or {}), **properties}
                edge.properties = merged
            return edge.id

        edge = KnowledgeEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            weight=weight,
            properties=properties or {},
        )
        db.add(edge)
        await db.flush()
        return edge.id

    # ---- Scan Learning ----

    @staticmethod
    async def learn_from_scan(db: AsyncSession, scan_id: str):
        """After a scan completes, build graph relationships from its results.

        Creates nodes for: domain, technologies, vuln types, WAFs, endpoints, techniques.
        Creates edges: domain->runs_on->tech, tech->vulnerable_to->vuln_type,
                       vuln_type->exploited_by->technique, waf->bypasses->technique,
                       endpoint->discovered_at->domain, tech->co_occurs_with->tech.
        """
        scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = scan_result.scalar_one_or_none()
        if not scan or scan.status != ScanStatus.COMPLETED:
            return

        target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
        target = target_result.scalar_one_or_none()
        if not target:
            return

        vulns_result = await db.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan_id)
        )
        vulns = vulns_result.scalars().all()

        domain = target.domain
        technologies = list((target.technologies or {}).get("summary", {}).keys())
        tech_lower = [t.lower().strip() for t in technologies if t.strip()]

        # Scan data may contain WAF info and recon results
        scan_data = scan.data or {}
        waf_info = scan_data.get("waf") or {}
        waf_name = None
        if isinstance(waf_info, dict):
            waf_name = waf_info.get("name") or waf_info.get("waf")
        elif isinstance(waf_info, str):
            waf_name = waf_info

        try:
            # 1. Domain node
            domain_id = await KnowledgeGraph.upsert_node(
                db, "domain", domain, {"target_id": target.id},
            )

            # 2. Technology nodes + domain->runs_on->tech edges
            tech_ids = {}
            for tech in tech_lower:
                tech_id = await KnowledgeGraph.upsert_node(db, "technology", tech)
                tech_ids[tech] = tech_id
                await KnowledgeGraph.add_edge(db, domain_id, tech_id, "runs_on")

            # 3. Tech co-occurrence edges (techs seen together on same target)
            tech_list = list(tech_ids.items())
            for i, (t1, id1) in enumerate(tech_list):
                for t2, id2 in tech_list[i + 1:]:
                    await KnowledgeGraph.add_edge(db, id1, id2, "co_occurs_with")
                    await KnowledgeGraph.add_edge(db, id2, id1, "co_occurs_with")

            # 4. WAF node + tech->bypasses edges
            waf_id = None
            if waf_name:
                waf_id = await KnowledgeGraph.upsert_node(
                    db, "waf", waf_name.lower().strip(),
                    {"detected_on": domain},
                )
                await KnowledgeGraph.add_edge(db, domain_id, waf_id, "runs_on")

            # 5. Vulnerability nodes + edges
            for v in vulns:
                vt = v.vuln_type.value
                vuln_node_id = await KnowledgeGraph.upsert_node(
                    db, "vulnerability", vt,
                    {"severity_counts": {v.severity.value: 1}},
                )

                # tech -> vulnerable_to -> vuln_type
                for tech, tech_id in tech_ids.items():
                    await KnowledgeGraph.add_edge(
                        db, tech_id, vuln_node_id, "vulnerable_to",
                        properties={"example_url": v.url[:500]},
                    )

                # vuln_type -> exploited_by -> technique (payload)
                payload = v.payload_used
                if payload and len(payload) >= 3:
                    technique_name = _payload_to_technique_name(vt, payload)
                    technique_id = await KnowledgeGraph.upsert_node(
                        db, "technique", technique_name,
                        {"payload": payload[:1000], "vuln_type": vt},
                    )
                    await KnowledgeGraph.add_edge(
                        db, vuln_node_id, technique_id, "exploited_by",
                        properties={"payload": payload[:500], "url": v.url[:500]},
                    )

                    # If WAF present, record bypass
                    if waf_id:
                        await KnowledgeGraph.add_edge(
                            db, technique_id, waf_id, "bypasses",
                            properties={"vuln_type": vt},
                        )

                # endpoint -> discovered_at -> domain
                if v.url:
                    try:
                        parsed = urlparse(v.url)
                        path = parsed.path or "/"
                        endpoint_name = f"{parsed.netloc}{path}"[:255]
                        endpoint_id = await KnowledgeGraph.upsert_node(
                            db, "endpoint", endpoint_name,
                            {"method": v.method, "parameter": v.parameter},
                        )
                        await KnowledgeGraph.add_edge(
                            db, endpoint_id, domain_id, "discovered_at",
                        )
                    except Exception:
                        pass

            # 6. Service nodes from port scan
            ports_data = target.ports or {}
            if isinstance(ports_data, dict):
                for port, info in ports_data.items():
                    service_name = info if isinstance(info, str) else (
                        info.get("service", f"port_{port}") if isinstance(info, dict) else f"port_{port}"
                    )
                    service_id = await KnowledgeGraph.upsert_node(
                        db, "service", f"{service_name}:{port}",
                        {"port": str(port), "service": service_name},
                    )
                    await KnowledgeGraph.add_edge(db, domain_id, service_id, "runs_on")

            await db.flush()
            logger.info(
                f"KnowledgeGraph: learned from scan {scan_id} "
                f"({len(tech_lower)} techs, {len(vulns)} vulns, domain={domain})"
            )

        except Exception as e:
            logger.error(f"KnowledgeGraph.learn_from_scan error: {e}", exc_info=True)

    # ---- Query Methods ----

    @staticmethod
    async def query_attack_surface(
        db: AsyncSession, technologies: list[str],
    ) -> dict:
        """Given detected techs, traverse graph to find known vulns and effective payloads.

        2-hop traversal:
          tech -[vulnerable_to]-> vuln_type -[exploited_by]-> technique
        Also queries WAF bypass info if WAF detected.
        Returns prioritized attack recommendations.
        """
        if not technologies:
            return {"vulnerabilities": [], "techniques": [], "waf_bypasses": []}

        tech_names = [t.lower().strip() for t in technologies]

        # Hop 1: tech -> vulnerable_to -> vuln_type
        n1 = aliased(KnowledgeNode, name="tech")
        e1 = aliased(KnowledgeEdge, name="e_vuln_to")
        n2 = aliased(KnowledgeNode, name="vuln")

        vuln_query = (
            select(
                n2.name.label("vuln_type"),
                n2.properties.label("vuln_props"),
                func.sum(e1.weight).label("total_weight"),
                func.count(e1.id).label("edge_count"),
            )
            .select_from(n1)
            .join(e1, n1.id == e1.source_id)
            .join(n2, e1.target_id == n2.id)
            .where(
                n1.node_type == "technology",
                n1.name.in_(tech_names),
                e1.edge_type == "vulnerable_to",
                n2.node_type == "vulnerability",
            )
            .group_by(n2.name, n2.properties)
            .order_by(func.sum(e1.weight).desc())
            .limit(20)
        )
        vuln_result = await db.execute(vuln_query)
        vulnerabilities = [
            {
                "vuln_type": row.vuln_type,
                "weight": float(row.total_weight),
                "observations": row.edge_count,
            }
            for row in vuln_result
        ]

        # Hop 2: vuln_type -> exploited_by -> technique (full 2-hop from tech)
        n3 = aliased(KnowledgeNode, name="technique")
        e2 = aliased(KnowledgeEdge, name="e_exploit")

        technique_query = (
            select(
                n3.name.label("technique"),
                n3.properties.label("technique_props"),
                e2.weight.label("weight"),
                n2.name.label("for_vuln"),
            )
            .select_from(n1)
            .join(e1, n1.id == e1.source_id)
            .join(n2, e1.target_id == n2.id)
            .join(e2, n2.id == e2.source_id)
            .join(n3, e2.target_id == n3.id)
            .where(
                n1.node_type == "technology",
                n1.name.in_(tech_names),
                e1.edge_type == "vulnerable_to",
                e2.edge_type == "exploited_by",
                n3.node_type == "technique",
            )
            .order_by(e2.weight.desc())
            .limit(30)
        )
        technique_result = await db.execute(technique_query)
        techniques = [
            {
                "technique": row.technique,
                "payload": (row.technique_props or {}).get("payload", ""),
                "for_vuln": row.for_vuln,
                "weight": float(row.weight),
            }
            for row in technique_result
        ]

        # WAF bypass: find WAFs co-located with these techs, then techniques that bypass them
        waf_node = aliased(KnowledgeNode, name="waf_node")
        bypass_tech = aliased(KnowledgeNode, name="bypass_tech")
        e_waf = aliased(KnowledgeEdge, name="e_waf_bypass")

        # First find WAFs on domains that run these techs
        # domain -> runs_on -> tech (known), domain -> runs_on -> waf
        domain_node = aliased(KnowledgeNode, name="domain_node")
        e_domain_tech = aliased(KnowledgeEdge, name="e_dt")
        e_domain_waf = aliased(KnowledgeEdge, name="e_dw")

        waf_bypass_query = (
            select(
                waf_node.name.label("waf"),
                bypass_tech.name.label("technique"),
                bypass_tech.properties.label("technique_props"),
                e_waf.weight.label("weight"),
            )
            .select_from(n1)
            .join(e_domain_tech, n1.id == e_domain_tech.target_id)
            .join(domain_node, and_(
                e_domain_tech.source_id == domain_node.id,
                domain_node.node_type == "domain",
            ))
            .join(e_domain_waf, and_(
                domain_node.id == e_domain_waf.source_id,
                e_domain_waf.edge_type == "runs_on",
            ))
            .join(waf_node, and_(
                e_domain_waf.target_id == waf_node.id,
                waf_node.node_type == "waf",
            ))
            .join(e_waf, and_(
                e_waf.target_id == waf_node.id,
                e_waf.edge_type == "bypasses",
            ))
            .join(bypass_tech, and_(
                e_waf.source_id == bypass_tech.id,
                bypass_tech.node_type == "technique",
            ))
            .where(
                n1.node_type == "technology",
                n1.name.in_(tech_names),
                e_domain_tech.edge_type == "runs_on",
            )
            .order_by(e_waf.weight.desc())
            .limit(15)
        )
        try:
            waf_result = await db.execute(waf_bypass_query)
            waf_bypasses = [
                {
                    "waf": row.waf,
                    "technique": row.technique,
                    "payload": (row.technique_props or {}).get("payload", ""),
                    "weight": float(row.weight),
                }
                for row in waf_result
            ]
        except Exception as e:
            logger.debug(f"WAF bypass query error (non-fatal): {e}")
            waf_bypasses = []

        return {
            "vulnerabilities": vulnerabilities,
            "techniques": techniques,
            "waf_bypasses": waf_bypasses,
        }

    @staticmethod
    async def find_similar_targets(
        db: AsyncSession, domain: str, technologies: list[str],
    ) -> list[dict]:
        """Find targets with similar tech stacks via shared technology nodes.

        Traverses: tech_node <-[runs_on]- other_domain, then collects vulns
        found on those domains.
        """
        if not technologies:
            return []

        tech_names = [t.lower().strip() for t in technologies]
        domain_lower = domain.lower().strip()

        # Find other domains sharing technologies
        tech_node = aliased(KnowledgeNode, name="tech")
        e_runs = aliased(KnowledgeEdge, name="e_runs")
        other_domain = aliased(KnowledgeNode, name="other_domain")

        similar_query = (
            select(
                other_domain.name.label("domain"),
                other_domain.properties.label("props"),
                func.count(tech_node.id).label("shared_techs"),
                func.array_agg(tech_node.name).label("technologies"),
            )
            .select_from(tech_node)
            .join(e_runs, tech_node.id == e_runs.target_id)
            .join(other_domain, and_(
                e_runs.source_id == other_domain.id,
                other_domain.node_type == "domain",
            ))
            .where(
                tech_node.node_type == "technology",
                tech_node.name.in_(tech_names),
                e_runs.edge_type == "runs_on",
                other_domain.name != domain_lower,
            )
            .group_by(other_domain.name, other_domain.properties)
            .order_by(func.count(tech_node.id).desc())
            .limit(10)
        )

        result = await db.execute(similar_query)
        similar_targets = []

        for row in result:
            # For each similar domain, find what vulns were discovered there
            e_vuln = aliased(KnowledgeEdge, name="e_v")
            vuln_n = aliased(KnowledgeNode, name="vuln_n")
            dom_n = aliased(KnowledgeNode, name="dom_n")
            tech_n2 = aliased(KnowledgeNode, name="tech_n2")
            e_tech = aliased(KnowledgeEdge, name="e_tech")

            vuln_query = (
                select(vuln_n.name.label("vuln_type"))
                .select_from(dom_n)
                .join(e_tech, dom_n.id == e_tech.source_id)
                .join(tech_n2, and_(
                    e_tech.target_id == tech_n2.id,
                    tech_n2.node_type == "technology",
                ))
                .join(e_vuln, and_(
                    tech_n2.id == e_vuln.source_id,
                    e_vuln.edge_type == "vulnerable_to",
                ))
                .join(vuln_n, and_(
                    e_vuln.target_id == vuln_n.id,
                    vuln_n.node_type == "vulnerability",
                ))
                .where(
                    dom_n.node_type == "domain",
                    dom_n.name == row.domain,
                    e_tech.edge_type == "runs_on",
                )
                .distinct()
                .limit(20)
            )
            vuln_result = await db.execute(vuln_query)
            found_vulns = [r.vuln_type for r in vuln_result]

            similar_targets.append({
                "domain": row.domain,
                "shared_technologies": list(set(row.technologies or [])),
                "shared_tech_count": row.shared_techs,
                "vulnerabilities_found": found_vulns,
            })

        return similar_targets

    @staticmethod
    async def get_tech_chain(db: AsyncSession, technology: str) -> dict:
        """Get full knowledge chain for a technology:
        tech -> vulnerable_to -> vuln types,
        tech -> co_occurs_with -> other techs,
        vuln -> exploited_by -> techniques.
        """
        tech_name = technology.lower().strip()

        # Find the tech node
        result = await db.execute(
            select(KnowledgeNode).where(
                and_(
                    KnowledgeNode.node_type == "technology",
                    KnowledgeNode.name == tech_name,
                )
            )
        )
        tech_node = result.scalar_one_or_none()
        if not tech_node:
            return {"technology": tech_name, "found": False}

        # Vulns: tech -> vulnerable_to -> vuln
        vuln_n = aliased(KnowledgeNode, name="vuln")
        e_v = aliased(KnowledgeEdge, name="e_v")
        vuln_query = (
            select(vuln_n.name, e_v.weight)
            .select_from(e_v)
            .join(vuln_n, e_v.target_id == vuln_n.id)
            .where(
                e_v.source_id == tech_node.id,
                e_v.edge_type == "vulnerable_to",
            )
            .order_by(e_v.weight.desc())
            .limit(20)
        )
        vuln_result = await db.execute(vuln_query)
        vulns = [{"vuln_type": r[0], "weight": float(r[1])} for r in vuln_result]

        # Co-occurring techs: tech -> co_occurs_with -> other_tech
        co_n = aliased(KnowledgeNode, name="co_tech")
        e_co = aliased(KnowledgeEdge, name="e_co")
        co_query = (
            select(co_n.name, e_co.weight)
            .select_from(e_co)
            .join(co_n, e_co.target_id == co_n.id)
            .where(
                e_co.source_id == tech_node.id,
                e_co.edge_type == "co_occurs_with",
            )
            .order_by(e_co.weight.desc())
            .limit(15)
        )
        co_result = await db.execute(co_query)
        co_techs = [{"technology": r[0], "weight": float(r[1])} for r in co_result]

        # Techniques: tech -> vulnerable_to -> vuln -> exploited_by -> technique (2-hop)
        tech_n = aliased(KnowledgeNode, name="technique")
        e_exploit = aliased(KnowledgeEdge, name="e_exploit")
        vuln_n2 = aliased(KnowledgeNode, name="vuln2")
        e_v2 = aliased(KnowledgeEdge, name="e_v2")

        technique_query = (
            select(
                tech_n.name.label("technique"),
                tech_n.properties.label("props"),
                e_exploit.weight.label("weight"),
                vuln_n2.name.label("for_vuln"),
            )
            .select_from(e_v2)
            .join(vuln_n2, e_v2.target_id == vuln_n2.id)
            .join(e_exploit, vuln_n2.id == e_exploit.source_id)
            .join(tech_n, e_exploit.target_id == tech_n.id)
            .where(
                e_v2.source_id == tech_node.id,
                e_v2.edge_type == "vulnerable_to",
                e_exploit.edge_type == "exploited_by",
            )
            .order_by(e_exploit.weight.desc())
            .limit(20)
        )
        technique_result = await db.execute(technique_query)
        techniques = [
            {
                "technique": r.technique,
                "payload": (r.props or {}).get("payload", ""),
                "for_vuln": r.for_vuln,
                "weight": float(r.weight),
            }
            for r in technique_result
        ]

        return {
            "technology": tech_name,
            "found": True,
            "scan_count": tech_node.scan_count,
            "first_seen": tech_node.first_seen.isoformat() if tech_node.first_seen else None,
            "vulnerabilities": vulns,
            "co_occurs_with": co_techs,
            "techniques": techniques,
        }

    @staticmethod
    async def get_graph_summary(db: AsyncSession) -> dict:
        """Return node/edge counts by type for monitoring and dashboard."""
        # Node counts by type
        node_query = (
            select(
                KnowledgeNode.node_type,
                func.count(KnowledgeNode.id),
            )
            .group_by(KnowledgeNode.node_type)
        )
        node_result = await db.execute(node_query)
        node_counts = {row[0]: row[1] for row in node_result}

        # Edge counts by type
        edge_query = (
            select(
                KnowledgeEdge.edge_type,
                func.count(KnowledgeEdge.id),
            )
            .group_by(KnowledgeEdge.edge_type)
        )
        edge_result = await db.execute(edge_query)
        edge_counts = {row[0]: row[1] for row in edge_result}

        # Totals
        total_nodes = sum(node_counts.values())
        total_edges = sum(edge_counts.values())

        # Top connected nodes (most edges)
        top_query = (
            select(
                KnowledgeNode.node_type,
                KnowledgeNode.name,
                KnowledgeNode.scan_count,
            )
            .order_by(KnowledgeNode.scan_count.desc())
            .limit(10)
        )
        top_result = await db.execute(top_query)
        top_nodes = [
            {"type": r[0], "name": r[1], "scan_count": r[2]}
            for r in top_result
        ]

        # Heaviest edges (highest weight)
        src = aliased(KnowledgeNode, name="src")
        tgt = aliased(KnowledgeNode, name="tgt")
        heavy_query = (
            select(
                src.name.label("source"),
                tgt.name.label("target"),
                KnowledgeEdge.edge_type,
                KnowledgeEdge.weight,
            )
            .join(src, KnowledgeEdge.source_id == src.id)
            .join(tgt, KnowledgeEdge.target_id == tgt.id)
            .order_by(KnowledgeEdge.weight.desc())
            .limit(10)
        )
        heavy_result = await db.execute(heavy_query)
        top_edges = [
            {
                "source": r.source,
                "target": r.target,
                "type": r.edge_type,
                "weight": float(r.weight),
            }
            for r in heavy_result
        ]

        return {
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "nodes_by_type": node_counts,
            "edges_by_type": edge_counts,
            "top_nodes": top_nodes,
            "top_edges": top_edges,
        }

    # ---- Context Enrichment for AI ----

    @staticmethod
    async def get_graph_context(
        db: AsyncSession, technologies: list[str], domain: str | None = None,
    ) -> dict:
        """Build a graph-based context block to enrich AI briefings.

        Combines attack surface analysis + similar targets into a concise summary.
        """
        attack_surface = await KnowledgeGraph.query_attack_surface(db, technologies)
        similar = []
        if domain:
            similar = await KnowledgeGraph.find_similar_targets(db, domain, technologies)

        return {
            "graph_attack_surface": attack_surface,
            "similar_targets": similar[:5],
        }


# ---- Helpers ----

def _payload_to_technique_name(vuln_type: str, payload: str) -> str:
    """Derive a short technique name from a payload string.
    Used as the knowledge node name for technique nodes."""
    # Truncate long payloads into a recognizable technique identifier
    payload_clean = payload.strip()[:80]
    # Remove noise characters for a cleaner name
    for ch in ["\n", "\r", "\t"]:
        payload_clean = payload_clean.replace(ch, " ")
    return f"{vuln_type}:{payload_clean}".lower()
