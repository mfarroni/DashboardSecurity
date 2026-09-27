import asyncio
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Dict, Any, Optional
import uuid

from app.core.database import SessionLocal, engine
from app.models.models import CVE, ImportBatch, FeedItem
from app.api.cve import nvd_client, parse_nvd_cve

logger = logging.getLogger("sync_worker")


class SyncWorker:
    def __init__(self):
        self._nvd_lock = asyncio.Lock()
        self._feed_lock = asyncio.Lock()

    async def run_nvd_sync(self, days: int = 7) -> Dict[str, Any]:
        """Runs NVD CVE sync with non-overlap lock and audit log tracking."""
        if self._nvd_lock.locked():
            return {"status": "skipped", "reason": "Sync NVD già in corso (non-overlap lock)"}

        async with self._nvd_lock:
            batch_id = str(uuid.uuid4())
            db: Session = SessionLocal()
            batch = ImportBatch(
                batch_id=batch_id,
                import_type="nvd_sync",
                filename=f"NVD Sync {days}d",
                status="running"
            )
            db.add(batch)
            db.commit()

            imported = 0
            updated = 0
            errors = []

            try:
                start_index = 0
                batch_size = 100

                while True:
                    data = await nvd_client.fetch_recent(days=days, start_index=start_index, results_per_page=batch_size)
                    vulns = data.get("vulnerabilities", [])
                    total_results = data.get("totalResults", 0)

                    if not vulns:
                        break

                    for vuln_wrapper in vulns:
                        try:
                            nvd_cve = vuln_wrapper.get("cve", {})
                            parsed = parse_nvd_cve(nvd_cve)
                            cve_id_str = parsed["cve_id"]

                            existing = db.query(CVE).filter(CVE.cve_id == cve_id_str).first()

                            if existing:
                                for key, value in parsed.items():
                                    if key != "cve_id":
                                        if key == "sources" and existing.sources:
                                            sources = set(existing.sources)
                                            sources.update(value)
                                            setattr(existing, key, list(sources))
                                        else:
                                            setattr(existing, key, value)
                                existing.updated_at = datetime.utcnow()
                                updated += 1
                            else:
                                new_cve = CVE(**parsed)
                                db.add(new_cve)
                                imported += 1

                            # Update SQLite FTS5 index if active
                            if "sqlite" in str(engine.url):
                                cpe_str = " ".join(parsed.get("cpe_matches") or [])
                                db.execute(
                                    text("INSERT OR REPLACE INTO cves_fts(cve_id, description, cpe_matches) VALUES (:cve_id, :desc, :cpe)"),
                                    {"cve_id": cve_id_str, "desc": parsed.get("description") or "", "cpe": cpe_str}
                                )
                        except Exception as e:
                            errors.append(f"{vuln_wrapper.get('cve', {}).get('id', 'unknown')}: {str(e)}")

                    db.commit()
                    start_index += batch_size
                    if start_index >= total_results:
                        break

                batch.records_total = imported + updated
                batch.records_imported = imported
                batch.records_failed = len(errors)
                batch.errors = errors if errors else None
                batch.completed_at = datetime.utcnow()
                batch.status = "completed" if not errors else "completed_with_errors"
                db.commit()

                return {
                    "status": "success",
                    "batch_id": batch_id,
                    "imported": imported,
                    "updated": updated,
                    "errors": errors
                }
            except Exception as e:
                batch.status = "failed"
                batch.errors = [str(e)]
                batch.completed_at = datetime.utcnow()
                db.commit()
                return {"status": "failed", "error": str(e)}
            finally:
                db.close()


sync_worker = SyncWorker()
