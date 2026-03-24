import asyncio
import time
from typing import Callable

import httpx

from depscore.config import Settings
from depscore.enrichment.github import GitHubEnricher
from depscore.enrichment.libraries_io import LibrariesIOEnricher
from depscore.enrichment.maven import MavenEnricher
from depscore.enrichment.npm import NpmEnricher
from depscore.enrichment.nuget import NuGetEnricher
from depscore.enrichment.osv import OSVEnricher
from depscore.enrichment.pypi import PyPIEnricher
from depscore.enrichment.scorecard import ScorecardEnricher
from depscore.models.dependency import EnrichedDependency
from depscore.models.sbom import SBOMComponent

ProgressCallback = Callable[[int, int, str], None]

# Registry enrichers keyed by ecosystem
_REGISTRY_ENRICHER_MAP = {
    "pypi": PyPIEnricher,
    "npm": NpmEnricher,
    "maven": MavenEnricher,
    "nuget": NuGetEnricher,
}


async def _enrich_one(
    component: SBOMComponent,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    github_enricher: GitHubEnricher,
    scorecard_enricher: ScorecardEnricher,
    osv_enricher: OSVEnricher,
    libraries_io_enricher: LibrariesIOEnricher,
    settings: Settings,
) -> EnrichedDependency:
    async with semaphore:
        start = time.monotonic()
        errors: list[str] = []

        # Determine registry enricher
        registry_enricher_cls = _REGISTRY_ENRICHER_MAP.get(component.ecosystem or "")
        registry_enricher = (
            registry_enricher_cls(
                timeout=settings.request_timeout_seconds,
                max_retries=settings.max_retries,
            )
            if registry_enricher_cls
            else None
        )

        tasks = {
            "github": github_enricher.enrich(component, client),
            "scorecard": scorecard_enricher.enrich(component, client),
            "osv": osv_enricher.enrich(component, client),
            "libraries_io": libraries_io_enricher.enrich(component, client),
        }
        if registry_enricher:
            tasks["registry"] = registry_enricher.enrich(component, client)

        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        result_map = dict(zip(tasks.keys(), results))

        dep = EnrichedDependency(component=component)

        for key, result in result_map.items():
            if isinstance(result, Exception):
                errors.append(f"{key}: {result}")
            else:
                setattr(dep, key if key != "registry" else "registry", result)

        dep.enrichment_errors = errors
        dep.enrichment_duration_seconds = time.monotonic() - start
        return dep


async def enrich_all(
    components: list[SBOMComponent],
    settings: Settings,
    progress_callback: ProgressCallback | None = None,
) -> list[EnrichedDependency]:
    semaphore = asyncio.Semaphore(settings.concurrency_limit)

    github_enricher = GitHubEnricher(
        token=settings.github_token,
        timeout=settings.request_timeout_seconds,
        max_retries=settings.max_retries,
    )
    scorecard_enricher = ScorecardEnricher(
        timeout=settings.request_timeout_seconds,
        max_retries=settings.max_retries,
    )
    osv_enricher = OSVEnricher(
        timeout=settings.request_timeout_seconds,
        max_retries=settings.max_retries,
    )
    libraries_io_enricher = LibrariesIOEnricher(
        api_key=settings.libraries_io_api_key,
        timeout=settings.request_timeout_seconds,
        max_retries=settings.max_retries,
    )

    total = len(components)
    completed = 0
    results: list[EnrichedDependency] = []

    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
        tasks = [
            _enrich_one(
                comp,
                client,
                semaphore,
                github_enricher,
                scorecard_enricher,
                osv_enricher,
                libraries_io_enricher,
                settings,
            )
            for comp in components
        ]

        for coro in asyncio.as_completed(tasks):
            enriched = await coro
            completed += 1
            if progress_callback:
                progress_callback(completed, total, enriched.component.name)
            results.append(enriched)

    # Restore original order
    name_to_results: dict[str, list[EnrichedDependency]] = {}
    for r in results:
        name_to_results.setdefault(r.component.name, []).append(r)

    ordered: list[EnrichedDependency] = []
    for comp in components:
        bucket = name_to_results.get(comp.name, [])
        if bucket:
            ordered.append(bucket.pop(0))

    return ordered
