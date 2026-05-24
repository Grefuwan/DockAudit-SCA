import docker
from docker.errors import DockerException

from dockaudit.image_analysis.package_extractor import PackageExtractor
from dockaudit.image_analysis.binary_analyzer import BinaryAnalyzer
from dockaudit.image_analysis.sbom_generator import SBOMGenerator
from dockaudit.sca.nvd_parser import NVDParser
from dockaudit.sca.vulnerability_matcher import VulnerabilityMatcher


class ImageAnalysis:
    def __init__(self, target="local", sbom_dir="reports/sbom", nvd_feed=None):
        self.target = target
        self.sbom_generator = SBOMGenerator(output_dir=sbom_dir)
        self.nvd_feed = nvd_feed
        self.package_extractor = None

    def run(self):
        try:
            client = docker.from_env()
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
                "sbom_path": None
            }

        findings = []

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
                "recommendation": recommendation
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
                packages, status = self.package_extractor.extract(image)
                if packages:
                    findings.append({
                        "id": f"IMG-PKG-{image.id[:8]}",
                        "title": f"Packages extracted for image {image.tags[0] if image.tags else image.id[:12]}",
                        "severity": "info",
                        "description": f"{len(packages)} packages were discovered and added to SBOM.",
                        "recommendation": "Use the SBOM and vulnerability report to review installed packages."
                    })
                    package_components.extend(packages)
                elif status == "no package manager found":
                    findings.append({
                        "id": f"IMG-PKG-NOMGR-{image.id[:8]}",
                        "title": f"No package manager detected for image {image.tags[0] if image.tags else image.id[:12]}",
                        "severity": "medium",
                        "description": "Unable to extract installed packages because the image has no supported package manager.",
                        "recommendation": "Consider scanning the image filesystem or using a different scanning approach."
                    })
                elif status != "ok":
                    findings.append({
                        "id": f"IMG-PKG-ERR-{image.id[:8]}",
                        "title": f"Package extraction failed for image {image.tags[0] if image.tags else image.id[:12]}",
                        "severity": "medium",
                        "description": status,
                        "recommendation": "Verify Docker can run the image and that the image supports package inspection."
                    })

        sbom_path, sbom_components = self.sbom_generator.generate(images, package_components=package_components)
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
            "binary_findings": binary_findings
        }
