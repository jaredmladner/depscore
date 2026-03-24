import json
from pathlib import Path
from typing import Any

from depscore.exceptions import SBOMParseError
from depscore.models.sbom import ParsedSBOM, SBOMComponent
from depscore.parsers.base import SBOMParser, ecosystem_from_purl


class CycloneDXParser(SBOMParser):
    def parse(self, path: Path) -> ParsedSBOM:
        try:
            data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SBOMParseError(f"Cannot read CycloneDX SBOM at {path}: {exc}") from exc

        if data.get("bomFormat") != "CycloneDX":
            raise SBOMParseError(f"{path} does not appear to be a CycloneDX BOM (missing bomFormat field)")

        spec_version = str(data.get("specVersion", "unknown"))
        serial_number = data.get("serialNumber")
        metadata = data.get("metadata", {})

        raw_components = data.get("components", [])
        components: list[SBOMComponent] = []
        for comp in raw_components:
            name = comp.get("name", "")
            if not name:
                continue
            version = comp.get("version")
            purl = comp.get("purl")
            ecosystem = ecosystem_from_purl(purl)

            # Try to get repo URL from externalRefs
            repo_url: str | None = None
            for ref in comp.get("externalReferences", []):
                if ref.get("type") in ("vcs", "website"):
                    url = ref.get("url", "")
                    if "github.com" in url or "gitlab.com" in url:
                        repo_url = url
                        break

            # License
            license_str: str | None = None
            licenses = comp.get("licenses", [])
            if licenses:
                first = licenses[0]
                if "license" in first:
                    license_str = first["license"].get("id") or first["license"].get("name")
                elif "expression" in first:
                    license_str = first["expression"]

            components.append(
                self._normalize_component(name, version, purl, repo_url, license_str)
            )

        return ParsedSBOM(
            format="cyclonedx",
            spec_version=spec_version,
            serial_number=serial_number,
            components=components,
            metadata=metadata,
        )
