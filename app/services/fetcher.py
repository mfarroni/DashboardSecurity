import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, List
from sqlalchemy.orm import Session
import httpx

from app.core.database import SessionLocal
from app.models.models import Provider, CVE, FeedItem, ProviderScope
from app.services.sync_worker import sync_worker
from app.services.notifier import notifier
from app.services.ioc_service import ioc_service
from app.services.relevance_calculator import relevance_calculator

logger = logging.getLogger("fetcher")


class BackgroundFetcher:
    def __init__(self, interval_seconds: int = 86400):  # Default 24h interval
        self.interval_seconds = interval_seconds
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def start(self):
        """Starts background periodic fetcher loop."""
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._run_loop())
            logger.info("Background Fetcher avviato")

    def stop(self):
        """Stops background periodic fetcher loop."""
        if self._running:
            self._running = False
            if self._task:
                self._task.cancel()
            logger.info("Background Fetcher arrestato")

    async def _run_loop(self):
        while self._running:
            try:
                logger.info("Avvio ciclo automatico di fetching feed e threat intelligence...")
                await self.execute_scheduled_fetch()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Errore durante l'esecuzione del ciclo Fetcher: {e}")

            await asyncio.sleep(self.interval_seconds)

    async def execute_scheduled_fetch(self) -> Dict[str, Any]:
        """Executes full automated fetch for all active registered providers."""
        db: Session = SessionLocal()
        results = {"nvd_sync": None, "providers_queried": 0, "alerts_triggered": 0}

        try:
            # 1. Automatic NVD Sync
            try:
                nvd_res = await sync_worker.run_nvd_sync(days=7)
                results["nvd_sync"] = nvd_res
            except Exception as e:
                logger.error(f"Errore NVD Sync automatico: {e}")
                results["nvd_sync"] = {"status": "error", "message": str(e)}

            # 2. Query Active Providers (MISP / CTI / SYSLOG)
            active_providers = db.query(Provider).filter(Provider.is_active == True).all()
            for provider in active_providers:
                if not provider.endpoint_url or not provider.api_key:
                    continue

                results["providers_queried"] += 1
                try:
                    await self._fetch_from_provider(db, provider)
                except Exception as e:
                    logger.error(f"Errore fetch da provider {provider.code}: {e}")

            # 3. Recalculate IoC Relevance Scores & Trigger Alerts
            iocs = ioc_service.list_iocs(db, limit=500)
            for ioc in iocs:
                ioc_tp = ioc.ioc_type.value if hasattr(ioc.ioc_type, 'value') else ioc.ioc_type
                score, match_type, asset_name = relevance_calculator.calculate_relevance(db, ioc_tp, ioc.value, ioc.tags)
                if score != ioc.relevance_score:
                    ioc.relevance_score = score
                    db.commit()

                # Trigger alert for high relevance IoCs (100% or 75%)
                if score >= 75:
                    alert_res = await notifier.send_alert(
                        title=f"Minaccia IoC Attinente al Perimetro ({score}%)",
                        message=f"Rilevato IoC '{ioc.value}' (Tipo: {ioc_tp}) con rilevanza {score}%. Correlazione: {match_type} ({asset_name or 'N/D'}).",
                        severity="CRITICAL" if score == 100 else "HIGH",
                        details={"ioc_id": ioc.id, "type": ioc_tp, "value": ioc.value, "match_type": match_type}
                    )
                    results["alerts_triggered"] += 1

            return results
        finally:
            db.close()

    async def _fetch_from_provider(self, db: Session, provider: Provider):
        """Simulates/Executes HTTP REST search query to Provider API."""
        headers = {"Authorization": f"Bearer {provider.api_key}", "Accept": "application/json"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                res = await client.get(provider.endpoint_url, headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    # Process MISP IoC events
                    if "MISP_IOC" in (provider.scopes or []) or ProviderScope.MISP_IOC in (provider.scopes or []):
                        records = []
                        if isinstance(data, list):
                            records = data
                        elif isinstance(data, dict) and "response" in data:
                            records = data["response"]
                        
                        if records:
                            ioc_service.ingest_ioc_batch(db, records, provider_name=provider.name)
                            logger.info(f"Importati {len(records)} IoC da provider {provider.name}")
            except Exception as e:
                logger.warning(f"Impossibile interrogare endpoint {provider.endpoint_url}: {e}")

fetcher = BackgroundFetcher()
