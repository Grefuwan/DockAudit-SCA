import logging

import docker
from docker.errors import DockerException

from dockaudit.image_analysis.package_extractor import PackageExtractor
from dockaudit.image_analysis.binary_analyzer import BinaryAnalyzer
from dockaudit.image_analysis.sbom_generator import SBOMGenerator
from dockaudit.sca.nvd_parser import NVDParser
from dockaudit.sca.vulnerability_matcher import VulnerabilityMatcher

logger = logging.getLogger(__name__)


class ImageAnalysis:
    def __init__(self, target="local", sbom_dir="reports/sbom", nvd_feed=None, container_filter=None, image_filter=None):
        self.target = target
        self.sbom_generator = SBOMGenerator(output_dir=sbom_dir)
        self.nvd_feed = nvd_feed
        self.package_extractor = None
        self.container_filter = container_filter
        self.image_filter = image_filter

    def run(self, sbom_filename=None):
        logger.debug("Iniciando análisis de imágenes Docker")
        try:
            client = docker.from_env()
            
            # Si hay un filtro de contenedor, solo analizar las imágenes de esos contenedores
            if self.container_filter:
                containers = client.containers.list(all=True)
                containers = [c for c in containers if c.name == self.container_filter or self.container_filter in c.name]
                
                if not containers:
                    return {
                        "findings": [],
                        "vulnerabilities": [],
                        "sbom_path": None,
                        "binary_findings": []
                    }
                
                # Obtener solo las imágenes de los contenedores filtrados
                image_ids = set(c.attrs.get("Image") for c in containers if c.attrs.get("Image"))
                images = []
                for image_id in image_ids:
                    try:
                        images.append(client.images.get(image_id))
                    except:
                        pass
            elif self.image_filter:
                all_images = client.images.list()
                images = [img for img in all_images if any(self.image_filter in tag for tag in img.tags)]
            else:
                images = client.images.list()
        except Exception as exc:
            return {
                "findings": [
                    {
                        "id": "IMG-000",
                        "title": "Docker API unavailable for image analysis",
                        "severity": "critical",
                        "description": str(exc),
                        "recommendation": "Verify Docker daemon is running and accessible."
                    }
                ],
                "vulnerabilities": [],
                "sbom_path": None,
                "binary_findings": []
            }

        findings = []
        images_metadata = []

        if not images:
            findings.append({
                "id": "IMG-001",
                "title": "No images found",
                "severity": "info",
                "description": "No Docker images were discovered on the host.",
                "recommendation": "Pull or build images to audit container images."
            })

        for image in images:
            tags = image.tags or ["<none>:<none>"]
            tag_string = ", ".join(tags)
            image_name = tags[0] if tags else "<none>:<none>"
            registry = self._extract_registry(image_name)
            healthcheck = bool(image.attrs.get("Config", {}).get("Healthcheck")) if getattr(image, "attrs", None) else False
            package_count = 0

            if self.package_extractor:
                packages, status = self.package_extractor.extract(image)
                package_count = len(packages) if isinstance(packages, list) else 0

            if any(tag.endswith(":latest") for tag in tags):
                severity = "medium"
                title = "Image tagged with latest"
                description = f"Image tags {tag_string} use the latest tag, which is not immutable."
                recommendation = "Use explicit immutable tags instead of 'latest'."
            elif any(tag.startswith("<none>") for tag in tags):
                severity = "medium"
                title = "Dangling or untagged image detected"
                description = f"Image with tags {tag_string} may be hard to manage or scan."
                recommendation = "Tag images explicitly and remove unused dangling images."
            else:
                severity = "info"
                title = "Image metadata recorded"
                description = f"Image tags: {tag_string}."
                recommendation = "Perform SBOM generation and vulnerability scanning for this image."

            findings.append({
                "id": f"IMG-{str(abs(hash(tag_string)))[:4]}",
                "title": title,
                "severity": severity,
                "description": description,
                "recommendation": recommendation,
                "source": image_name,
                "source_type": "image"
            })

            img_env_vars = {}
            for env_str in (getattr(image, "attrs", {}) or {}).get("Config", {}).get("Env", []) or []:
                if "=" in env_str:
                    key, _, val = env_str.partition("=")
                    img_env_vars[key] = val

            images_metadata.append({
                "name": image_name,
                "registry": registry,
                "tags": tags,
                "healthcheck": healthcheck,
                "packages": package_count,
                "env_vars": img_env_vars,
                "is_official": "/" not in image_name.replace("docker.io/library/", "").split(":")[0]
            })

        try:
            client = docker.from_env()
            self.package_extractor = PackageExtractor(client)
            binary_analyzer = BinaryAnalyzer(client)
            binary_findings = binary_analyzer.analyze_images(images)
        except Exception:
            client = None
            binary_findings = []

        package_components = []
        for image in images:
            if self.package_extractor:
                image_tag = image.tags[0] if image.tags else image.id[:12]
                packages, status = self.package_extractor.extract(image, timeout=120)
                if packages:
                    for pkg in packages:
                        pkg["image"] = image_tag
                    findings.append({
                        "id": f"IMG-PKG-{image.id[:8]}",
                        "title": f"Packages extracted for image {image_tag}",
                        "severity": "info",
                        "description": f"{len(packages)} packages were discovered and added to SBOM.",
                        "recommendation": "Use the SBOM and vulnerability report to review installed packages.",
                        "source": image_tag,
                        "source_type": "image"
                    })
                    package_components.extend(packages)
                elif status == "no package manager found":
                    findings.append({
                        "id": f"IMG-PKG-NOMGR-{image.id[:8]}",
                        "title": f"No package manager detected for image {image_tag}",
                        "severity": "medium",
                        "description": "Unable to extract installed packages because the image has no supported package manager.",
                        "recommendation": "Consider scanning the image filesystem or using a different scanning approach.",
                        "source": image_tag,
                        "source_type": "image"
                    })
                elif status != "ok":
                    findings.append({
                        "id": f"IMG-PKG-ERR-{image.id[:8]}",
                        "title": f"Package extraction failed for image {image_tag}",
                        "severity": "medium",
                        "description": status,
                        "recommendation": "Verify Docker can run the image and that the image supports package inspection.",
                        "source": image_tag,
                        "source_type": "image"
                    })

        sbom_path, sbom_components = self.sbom_generator.generate(images, package_components=package_components, filename=sbom_filename)
        vulnerabilities = []

        if self.nvd_feed:
            try:
                nvd_entries = NVDParser().load_feed(self.nvd_feed)
                vulnerabilities = VulnerabilityMatcher(nvd_entries).match_components(package_components)
            except Exception as exc:
                findings.append({
                    "id": "IMG-999",
                    "title": "NVD feed processing failed",
                    "severity": "medium",
                    "description": str(exc),
                    "recommendation": "Verify the NVD feed path and format."
                })

        return {
            "findings": findings,
            "vulnerabilities": vulnerabilities,
            "sbom_path": sbom_path,
            "binary_findings": binary_findings,
            "images": images_metadata,
            "packages": package_components
        }

    def _extract_registry(self, image_name):
        if not image_name:
            return ""

        if "/" not in image_name:
            return "docker.io"

        parts = image_name.split("/")
        if "." in parts[0] or ":" in parts[0]:
            return parts[0]

        return "docker.io"
