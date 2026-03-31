import json
from pathlib import Path
from typing import Any

from depscore.exceptions import SBOMParseError
from depscore.models.sbom import ParsedSBOM, SBOMComponent
from depscore.parsers.base import SBOMParser


class SPDXParser(SBOMParser):
    def parse(self, path: Path) -> ParsedSBOM:
        try:
            data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SBOMParseError(f"Cannot read SPDX SBOM at {path}: {exc}") from exc

        spdx_version = data.get("spdxVersion", "")
        if not spdx_version.startswith("SPDX-"):
            raise SBOMParseError(f"{path} does not appear to be a valid SPDX document")

        spec_version = spdx_version
        doc_name = data.get("name", "")
        metadata: dict[str, Any] = {
            "name": doc_name,
            "dataLicense": data.get("dataLicense"),
            "documentNamespace": data.get("documentNamespace"),
        }

        # Build a license lookup from hasExtractedLicensingInfos if present
        license_map: dict[str, str] = {}
        for info in data.get("hasExtractedLicensingInfos", []):
            lid = info.get("licenseId", "")
            name = info.get("name", lid)
            license_map[lid] = name

        raw_packages = data.get("packages", [])
        components: list[SBOMComponent] = []
        for pkg in raw_packages:
            name = pkg.get("name", "")
            if not name:
                continue
            # Skip the document root package
            if pkg.get("SPDXID") == "SPDXRef-DOCUMENT":
                continue

            version = pkg.get("versionInfo")
            if version in ("NOASSERTION", "NONE", ""):
                version = None

            # Extract PURL from externalRefs
            purl: str | None = None
            repo_url: str | None = None
            for ref in pkg.get("externalRefs", []):
                ref_type = ref.get("referenceType", "")
                ref_locator = ref.get("referenceLocator", "")
                if ref_type == "purl" and ref_locator.startswith("pkg:"):
                    purl = ref_locator
                if ref_type in ("url", "website") and (
                    "github.com" in ref_locator or "gitlab.com" in ref_locator
                ):
                    repo_url = ref_locator

            # Download location may be a VCS URL
            download_loc = pkg.get("downloadLocation", "")
            if not repo_url and download_loc not in ("NOASSERTION", "NONE", ""):
                if "github.com" in download_loc or "gitlab.com" in download_loc:
                    repo_url = download_loc.split("+")[-1].split("@")[0]

            # License
            license_str: str | None = None
            concluded = pkg.get("licenseConcluded", "NOASSERTION")
            declared = pkg.get("licenseDeclared", "NOASSERTION")
            for lic in (concluded, declared):
                if lic and lic not in ("NOASSERTION", "NONE"):
                    license_str = license_map.get(lic, lic)
                    break

            components.append(
                self._normalize_component(name, version, purl, repo_url, license_str)
            )

        return ParsedSBOM(
            format="spdx",
            spec_version=spec_version,
            serial_number=None,
            components=components,
            metadata=metadata,
        )
