from pathlib import Path

EXT_MAP = {
    ".py":    "python",
    ".js":    "javascript",
    ".ts":    "typescript",
    ".jsx":   "javascript",
    ".tsx":   "typescript",
    ".java":  "java",
    ".php":   "php",
    ".go":    "go",
    ".rb":    "ruby",
    ".cs":    "csharp",
    ".cpp":   "cpp",
    ".c":     "c",
    ".rs":    "rust",
    ".kt":    "kotlin",
    ".swift": "swift",
    ".scala": "scala",
    ".r":     "r",
    ".m":     "objc",
}

FILENAME_MAP = {
    "Dockerfile":   "docker",
    ".env":         "config",
    "requirements.txt": "python",
    "package.json": "javascript",
    "pom.xml":      "java",
    "build.gradle": "java",
    "Gemfile":      "ruby",
    "go.mod":       "go",
    "Cargo.toml":   "rust",
}


def detect_languages(code_path: str) -> list:
    langs = set()
    root = Path(code_path)

    for f in root.rglob("*"):
        if not f.is_file():
            continue
        # Skip common non-source dirs
        parts = f.parts
        if any(p in parts for p in [
            ".git", "node_modules",
            "__pycache__", "venv", ".venv",
            "dist", "build", "target",
        ]):
            continue

        ext = f.suffix.lower()
        if ext in EXT_MAP:
            langs.add(EXT_MAP[ext])

        if f.name in FILENAME_MAP:
            langs.add(FILENAME_MAP[f.name])

    return sorted(list(langs))


def has_language(
    code_path: str, lang: str
) -> bool:
    return lang in detect_languages(code_path)
