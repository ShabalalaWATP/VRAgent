"""
Campaign Persistence Service

Database persistence for agentic binary fuzzing campaigns.
Handles saving and loading campaign state for recovery and history.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.core.database import get_db

logger = logging.getLogger(__name__)


# =============================================================================
# Campaign Persistence Service
# =============================================================================

class CampaignPersistenceService:
    """
    Handles database persistence for fuzzing campaigns.

    Provides save/load operations with error handling and
    graceful degradation when database is unavailable.
    """

    def __init__(self, db: Optional[Session] = None):
        self._db = db
        self._db_available = self._check_db_available()

    def _check_db_available(self) -> bool:
        """Check if database is available."""
        try:
            if self._db:
                self._db.execute(text("SELECT 1"))
                return True
            return False
        except Exception as e:
            logger.warning(f"Database not available: {e}")
            return False

    def _get_db(self) -> Optional[Session]:
        """Get database session."""
        if self._db:
            return self._db

        try:
            return next(get_db())
        except Exception:
            return None

    # =========================================================================
    # Campaign Operations
    # =========================================================================

    async def save_campaign(
        self,
        campaign_id: str,
        binary_hash: str,
        binary_name: str,
        status: str,
        config: Dict[str, Any],
        profile: Optional[Dict[str, Any]] = None,
        plan: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Save or update a campaign record.
        """
        db = self._get_db()
        if not db:
            logger.debug("Database unavailable, skipping campaign save")
            return False

        try:
            # Check if campaign exists
            result = db.execute(
                text("SELECT id FROM agentic_binary_campaigns WHERE campaign_id = :cid"),
                {"cid": campaign_id}
            )
            existing = result.fetchone()

            if existing:
                # Update
                db.execute(
                    text("""
                        UPDATE agentic_binary_campaigns
                        SET status = :status,
                            config_json = :config,
                            binary_profile = :profile,
                            campaign_plan = :plan
                        WHERE campaign_id = :cid
                    """),
                    {
                        "cid": campaign_id,
                        "status": status,
                        "config": json.dumps(config) if config else None,
                        "profile": json.dumps(profile) if profile else None,
                        "plan": json.dumps(plan) if plan else None,
                    }
                )
            else:
                # Insert
                db.execute(
                    text("""
                        INSERT INTO agentic_binary_campaigns
                        (campaign_id, binary_hash, binary_name, status, config_json, binary_profile, campaign_plan, started_at)
                        VALUES (:cid, :bhash, :bname, :status, :config, :profile, :plan, :started)
                    """),
                    {
                        "cid": campaign_id,
                        "bhash": binary_hash,
                        "bname": binary_name,
                        "status": status,
                        "config": json.dumps(config) if config else None,
                        "profile": json.dumps(profile) if profile else None,
                        "plan": json.dumps(plan) if plan else None,
                        "started": datetime.utcnow(),
                    }
                )

            db.commit()
            return True

        except Exception as e:
            logger.error(f"Failed to save campaign {campaign_id}: {e}")
            db.rollback()
            return False

    async def update_campaign_metrics(
        self,
        campaign_id: str,
        total_executions: int,
        coverage_percentage: float,
        edges_discovered: int,
        unique_crashes: int,
        exploitable_crashes: int,
        corpus_size: int,
        current_strategy: str,
    ) -> bool:
        """
        Update campaign metrics.
        """
        db = self._get_db()
        if not db:
            return False

        try:
            db.execute(
                text("""
                    UPDATE agentic_binary_campaigns
                    SET total_executions = :exec,
                        coverage_percentage = :cov,
                        edges_discovered = :edges,
                        unique_crashes = :crashes,
                        exploitable_crashes = :exploit,
                        corpus_size = :corpus,
                        current_strategy = :strategy
                    WHERE campaign_id = :cid
                """),
                {
                    "cid": campaign_id,
                    "exec": total_executions,
                    "cov": coverage_percentage,
                    "edges": edges_discovered,
                    "crashes": unique_crashes,
                    "exploit": exploitable_crashes,
                    "corpus": corpus_size,
                    "strategy": current_strategy,
                }
            )
            db.commit()
            return True

        except Exception as e:
            logger.error(f"Failed to update campaign metrics: {e}")
            db.rollback()
            return False

    async def update_campaign_status(
        self,
        campaign_id: str,
        status: str,
        ended_at: Optional[datetime] = None,
    ) -> bool:
        """
        Update campaign status.
        """
        db = self._get_db()
        if not db:
            return False

        try:
            if ended_at:
                db.execute(
                    text("""
                        UPDATE agentic_binary_campaigns
                        SET status = :status, ended_at = :ended
                        WHERE campaign_id = :cid
                    """),
                    {"cid": campaign_id, "status": status, "ended": ended_at}
                )
            else:
                db.execute(
                    text("""
                        UPDATE agentic_binary_campaigns
                        SET status = :status
                        WHERE campaign_id = :cid
                    """),
                    {"cid": campaign_id, "status": status}
                )

            db.commit()
            return True

        except Exception as e:
            logger.error(f"Failed to update campaign status: {e}")
            db.rollback()
            return False

    async def load_campaign(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """
        Load a campaign record.
        """
        db = self._get_db()
        if not db:
            return None

        try:
            result = db.execute(
                text("""
                    SELECT * FROM agentic_binary_campaigns
                    WHERE campaign_id = :cid
                """),
                {"cid": campaign_id}
            )
            row = result.fetchone()

            if not row:
                return None

            return {
                "campaign_id": row.campaign_id,
                "binary_hash": row.binary_hash,
                "binary_name": row.binary_name,
                "status": row.status,
                "current_strategy": row.current_strategy,
                "total_executions": row.total_executions,
                "coverage_percentage": row.coverage_percentage,
                "unique_crashes": row.unique_crashes,
                "exploitable_crashes": row.exploitable_crashes,
                "config": json.loads(row.config_json) if row.config_json else {},
                "profile": json.loads(row.binary_profile) if row.binary_profile else None,
                "plan": json.loads(row.campaign_plan) if row.campaign_plan else None,
                "started_at": row.started_at.isoformat() if row.started_at else None,
                "ended_at": row.ended_at.isoformat() if row.ended_at else None,
            }

        except Exception as e:
            logger.error(f"Failed to load campaign {campaign_id}: {e}")
            return None

    async def list_campaigns(
        self,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        List campaigns, optionally filtered by status.
        """
        db = self._get_db()
        if not db:
            return []

        try:
            if status:
                result = db.execute(
                    text("""
                        SELECT campaign_id, binary_name, status, started_at, ended_at,
                               total_executions, coverage_percentage, unique_crashes
                        FROM agentic_binary_campaigns
                        WHERE status = :status
                        ORDER BY started_at DESC
                        LIMIT :lim
                    """),
                    {"status": status, "lim": limit}
                )
            else:
                result = db.execute(
                    text("""
                        SELECT campaign_id, binary_name, status, started_at, ended_at,
                               total_executions, coverage_percentage, unique_crashes
                        FROM agentic_binary_campaigns
                        ORDER BY started_at DESC
                        LIMIT :lim
                    """),
                    {"lim": limit}
                )

            campaigns = []
            for row in result.fetchall():
                campaigns.append({
                    "campaign_id": row.campaign_id,
                    "binary_name": row.binary_name,
                    "status": row.status,
                    "started_at": row.started_at.isoformat() if row.started_at else None,
                    "ended_at": row.ended_at.isoformat() if row.ended_at else None,
                    "total_executions": row.total_executions,
                    "coverage_percentage": row.coverage_percentage,
                    "unique_crashes": row.unique_crashes,
                })

            return campaigns

        except Exception as e:
            logger.error(f"Failed to list campaigns: {e}")
            return []

    # =========================================================================
    # Decision Operations
    # =========================================================================

    async def save_decision(
        self,
        campaign_id: str,
        decision_id: str,
        decision_type: str,
        reasoning: str,
        parameters: Dict[str, Any],
        coverage_at_decision: float,
        crashes_at_decision: int,
    ) -> bool:
        """
        Save an AI decision.
        """
        db = self._get_db()
        if not db:
            return False

        try:
            db.execute(
                text("""
                    INSERT INTO agentic_campaign_decisions
                    (campaign_id, decision_id, decision_type, reasoning, parameters,
                     coverage_at_decision, crashes_at_decision, created_at)
                    VALUES (:cid, :did, :dtype, :reason, :params, :cov, :crashes, :created)
                """),
                {
                    "cid": campaign_id,
                    "did": decision_id,
                    "dtype": decision_type,
                    "reason": reasoning,
                    "params": json.dumps(parameters) if parameters else None,
                    "cov": coverage_at_decision,
                    "crashes": crashes_at_decision,
                    "created": datetime.utcnow(),
                }
            )
            db.commit()
            return True

        except Exception as e:
            logger.error(f"Failed to save decision: {e}")
            db.rollback()
            return False

    async def load_decisions(
        self,
        campaign_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Load decisions for a campaign.
        """
        db = self._get_db()
        if not db:
            return []

        try:
            result = db.execute(
                text("""
                    SELECT * FROM agentic_campaign_decisions
                    WHERE campaign_id = :cid
                    ORDER BY created_at DESC
                    LIMIT :lim
                """),
                {"cid": campaign_id, "lim": limit}
            )

            decisions = []
            for row in result.fetchall():
                decisions.append({
                    "decision_id": row.decision_id,
                    "decision_type": row.decision_type,
                    "reasoning": row.reasoning,
                    "parameters": json.loads(row.parameters) if row.parameters else {},
                    "coverage_at_decision": row.coverage_at_decision,
                    "crashes_at_decision": row.crashes_at_decision,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                })

            return decisions

        except Exception as e:
            logger.error(f"Failed to load decisions: {e}")
            return []

    # =========================================================================
    # Crash Operations
    # =========================================================================

    async def save_crash(
        self,
        campaign_id: str,
        crash_id: str,
        crash_hash: str,
        crash_type: str,
        exploitability: str,
        confidence: float,
        input_size: int,
        root_cause: Optional[str] = None,
        exploit_primitives: Optional[List[str]] = None,
    ) -> bool:
        """
        Save a triaged crash.
        """
        db = self._get_db()
        if not db:
            return False

        try:
            db.execute(
                text("""
                    INSERT INTO agentic_triaged_crashes
                    (campaign_id, crash_id, crash_hash, crash_type, exploitability,
                     confidence, input_size, root_cause, exploit_primitives, discovered_at)
                    VALUES (:cid, :crid, :chash, :ctype, :exploit, :conf, :size, :cause, :prims, :disc)
                    ON CONFLICT (crash_id) DO NOTHING
                """),
                {
                    "cid": campaign_id,
                    "crid": crash_id,
                    "chash": crash_hash,
                    "ctype": crash_type,
                    "exploit": exploitability,
                    "conf": confidence,
                    "size": input_size,
                    "cause": root_cause,
                    "prims": json.dumps(exploit_primitives) if exploit_primitives else None,
                    "disc": datetime.utcnow(),
                }
            )
            db.commit()
            return True

        except Exception as e:
            logger.error(f"Failed to save crash: {e}")
            db.rollback()
            return False

    async def load_crashes(
        self,
        campaign_id: str,
        exploitability_filter: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Load crashes for a campaign.
        """
        db = self._get_db()
        if not db:
            return []

        try:
            if exploitability_filter:
                result = db.execute(
                    text("""
                        SELECT * FROM agentic_triaged_crashes
                        WHERE campaign_id = :cid AND exploitability = :exp
                        ORDER BY discovered_at DESC
                        LIMIT :lim
                    """),
                    {"cid": campaign_id, "exp": exploitability_filter, "lim": limit}
                )
            else:
                result = db.execute(
                    text("""
                        SELECT * FROM agentic_triaged_crashes
                        WHERE campaign_id = :cid
                        ORDER BY discovered_at DESC
                        LIMIT :lim
                    """),
                    {"cid": campaign_id, "lim": limit}
                )

            crashes = []
            for row in result.fetchall():
                crashes.append({
                    "crash_id": row.crash_id,
                    "crash_hash": row.crash_hash,
                    "crash_type": row.crash_type,
                    "exploitability": row.exploitability,
                    "confidence": row.confidence,
                    "input_size": row.input_size,
                    "root_cause": row.root_cause,
                    "exploit_primitives": json.loads(row.exploit_primitives) if row.exploit_primitives else [],
                    "discovered_at": row.discovered_at.isoformat() if row.discovered_at else None,
                })

            return crashes

        except Exception as e:
            logger.error(f"Failed to load crashes: {e}")
            return []

    # =========================================================================
    # Coverage Snapshot Operations
    # =========================================================================

    async def save_coverage_snapshot(
        self,
        campaign_id: str,
        coverage_percentage: float,
        edges_discovered: int,
        total_executions: int,
        corpus_size: int,
        execs_per_sec: float,
        unique_crashes: int,
        current_strategy: str,
    ) -> bool:
        """
        Save a coverage snapshot for trend analysis.
        """
        db = self._get_db()
        if not db:
            return False

        try:
            db.execute(
                text("""
                    INSERT INTO agentic_coverage_snapshots
                    (campaign_id, coverage_percentage, edges_discovered, total_executions,
                     corpus_size, execs_per_sec, unique_crashes, current_strategy, timestamp)
                    VALUES (:cid, :cov, :edges, :exec, :corpus, :eps, :crashes, :strat, :ts)
                """),
                {
                    "cid": campaign_id,
                    "cov": coverage_percentage,
                    "edges": edges_discovered,
                    "exec": total_executions,
                    "corpus": corpus_size,
                    "eps": execs_per_sec,
                    "crashes": unique_crashes,
                    "strat": current_strategy,
                    "ts": datetime.utcnow(),
                }
            )
            db.commit()
            return True

        except Exception as e:
            logger.error(f"Failed to save coverage snapshot: {e}")
            db.rollback()
            return False

    async def load_coverage_history(
        self,
        campaign_id: str,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """
        Load coverage history for a campaign.
        """
        db = self._get_db()
        if not db:
            return []

        try:
            result = db.execute(
                text("""
                    SELECT * FROM agentic_coverage_snapshots
                    WHERE campaign_id = :cid
                    ORDER BY timestamp ASC
                    LIMIT :lim
                """),
                {"cid": campaign_id, "lim": limit}
            )

            history = []
            for row in result.fetchall():
                history.append({
                    "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                    "coverage_percentage": row.coverage_percentage,
                    "edges_discovered": row.edges_discovered,
                    "total_executions": row.total_executions,
                    "corpus_size": row.corpus_size,
                    "execs_per_sec": row.execs_per_sec,
                    "unique_crashes": row.unique_crashes,
                    "current_strategy": row.current_strategy,
                })

            return history

        except Exception as e:
            logger.error(f"Failed to load coverage history: {e}")
            return []


# =============================================================================
# Convenience Functions
# =============================================================================

def get_persistence_service(db: Optional[Session] = None) -> CampaignPersistenceService:
    """Get a persistence service instance."""
    return CampaignPersistenceService(db)
