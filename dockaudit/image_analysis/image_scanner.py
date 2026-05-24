class ImageAnalysis:
    def __init__(self, target="local"):
        self.target = target

    def run(self):
        """Implementación mínima que devuelve lista de hallazgos de imágenes.
        """
        return [
            {
                "id": "IMG-001",
                "title": "No images scanned",
                "severity": "info",
                "description": "Image analysis is not configured in this minimal demo.",
                "recommendation": "Enable image scanning plugins or provide image list."
            }
        ]
