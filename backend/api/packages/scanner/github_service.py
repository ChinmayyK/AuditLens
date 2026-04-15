import os
import re
import subprocess
from pathlib import Path
from typing import Optional
import logging

import httpx

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".php", ".go", ".rb", ".cs",
    ".cpp", ".c", ".rs", ".kt", ".swift",
    ".html", ".css", ".json", ".yaml",
    ".yml", ".env", ".md", ".sh", ".bash",
    ".toml", ".ini", ".cfg", ".conf",
    ".dockerfile", ".tf",
}

SUPPORTED_FILENAMES = {
    "Dockerfile", ".gitignore",
    "requirements.txt", "package.json",
    "pom.xml", "build.gradle",
    "Gemfile", "go.mod", "Cargo.toml",
    ".env.example",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__",
    "venv", ".venv", "dist", "build",
    "target", ".gradle", "vendor",
    "coverage", ".nyc_output",
}

MAX_FILE_SIZE = 100 * 1024   # 100KB
MAX_FILES     = 300


class GitHubService:

    def clone_repo(
        self, repo_url: str, session_id: str
    ) -> dict:
        clone_dir = (
            f"/tmp/shieldsentinel/ide/{session_id}"
        )
        os.makedirs(clone_dir, exist_ok=True)

        # Sanitize URL
        url = repo_url.strip().rstrip("/")
        if "github.com" not in url:
            raise ValueError(
                "Only GitHub repos supported"
            )
        if "?" in url:
            url = url.split("?", 1)[0]
        if "#" in url:
            url = url.split("#", 1)[0]
        if not url.endswith(".git"):
            git_url = url + ".git"
        else:
            git_url = url

        result = subprocess.run(
            [
                "git", "clone",
                "--depth=1",
                "--single-branch",
                git_url,
                clone_dir,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Git clone failed: "
                f"{result.stderr[:200]}"
            )

        file_tree     = self._build_tree(clone_dir)
        file_contents = self._index_files(clone_dir)

        return {
            "clone_path":    clone_dir,
            "file_tree":     file_tree,
            "file_contents": file_contents,
        }

    def _build_tree(self, root: str) -> list:
        root_path = Path(root)

        def build_node(path: Path) -> dict:
            rel = str(path.relative_to(root_path))
            node = {
                "name":      path.name,
                "path":      rel,
                "type":
                    "directory"
                    if path.is_dir()
                    else "file",
                "extension":
                    path.suffix.lower()
                    if path.is_file() else None,
            }
            if path.is_dir():
                children = []
                try:
                    for item in sorted(
                        path.iterdir(),
                        key=lambda p: (
                            p.is_file(), p.name
                        ),
                    ):
                        if item.name in SKIP_DIRS:
                            continue
                        if item.name.startswith(".") \
                           and item.name not in {
                               ".env",
                               ".gitignore",
                               ".env.example",
                           }:
                            continue
                        children.append(
                            build_node(item)
                        )
                except PermissionError:
                    pass
                node["children"] = children
            return node

        tree = []
        for item in sorted(
            root_path.iterdir(),
            key=lambda p: (p.is_file(), p.name),
        ):
            if item.name in SKIP_DIRS:
                continue
            if item.name == ".git":
                continue
            tree.append(build_node(item))
        return tree

    def _index_files(self, root: str) -> dict:
        root_path = Path(root)
        contents  = {}
        count     = 0

        for f in root_path.rglob("*"):
            if count >= MAX_FILES:
                break
            if not f.is_file():
                continue
            if any(s in f.parts for s in SKIP_DIRS):
                continue

            ok = (
                f.suffix.lower() in
                SUPPORTED_EXTENSIONS or
                f.name in SUPPORTED_FILENAMES
            )
            if not ok:
                continue

            try:
                size = f.stat().st_size
                if size > MAX_FILE_SIZE:
                    continue
                content = f.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
                rel = str(f.relative_to(root_path))
                contents[rel] = content
                count += 1
            except Exception:
                continue

        return contents

    # ── PR-specific methods ────────────────────────────

    def _github_headers(self) -> dict:
        """Build auth headers for GitHub API requests."""
        token = os.getenv("GITHUB_TOKEN", "")
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def parse_repo_url(
        self, repo_url: str
    ) -> tuple[str, str]:
        """
        Extract (owner, repo_name) from a GitHub URL.

        Supports:
          https://github.com/owner/repo
          https://github.com/owner/repo.git
          http://github.com/owner/repo/

        Returns:
            Tuple of (owner, repo_name).

        Raises:
            ValueError: If URL is not a valid GitHub repo URL.
        """
        url = repo_url.strip().rstrip("/")
        if "github.com" not in url:
            raise ValueError(
                "Only GitHub repos supported"
            )
        # Strip query/fragment
        url = url.split("?", 1)[0].split("#", 1)[0]
        # Strip .git suffix
        if url.endswith(".git"):
            url = url[:-4]
        # Extract owner/repo from path
        parts = (
            url.replace("https://", "")
            .replace("http://", "")
            .strip("/")
            .split("/")
        )
        if len(parts) < 3:
            raise ValueError(
                "URL must be github.com/owner/repo"
            )
        return parts[1], parts[2]

    def fetch_pr_metadata(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> dict:
        """
        Fetch PR metadata from GitHub REST API.

        GET /repos/{owner}/{repo}/pulls/{pr_number}

        Returns:
            Dict with head_sha, base_branch, head_branch,
            title, author, and html_url.
        """
        url = (
            f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
            f"/pulls/{pr_number}"
        )
        resp = httpx.get(
            url,
            headers=self._github_headers(),
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        return {
            "owner": owner,
            "repo": repo,
            "pr_number": pr_number,
            "head_sha": data["head"]["sha"],
            "base_branch": data["base"]["ref"],
            "head_branch": data["head"]["ref"],
            "title": data.get("title", ""),
            "author": (
                data.get("user", {}).get("login", "")
            ),
            "html_url": data.get("html_url", ""),
            "clone_url": (
                data.get("head", {})
                .get("repo", {})
                .get("clone_url", "")
            ),
        }

    def fetch_pr_diff(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> str:
        """
        Fetch the unified diff for a PR.

        GET /repos/{owner}/{repo}/pulls/{pr_number}
        Accept: application/vnd.github.v3.diff

        Returns:
            Raw unified diff text for the entire PR.
        """
        url = (
            f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
            f"/pulls/{pr_number}"
        )
        headers = self._github_headers()
        headers["Accept"] = (
            "application/vnd.github.v3.diff"
        )

        resp = httpx.get(
            url,
            headers=headers,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.text

    def split_diff_by_file(
        self, full_diff: str
    ) -> dict[str, str]:
        """
        Split a full PR unified diff into per-file diffs.

        Dev 2's DiffAnalyzer.parse() expects:
            dict[str, str]  (file_path → per-file diff)

        Splits on 'diff --git a/... b/...' headers and
        strips a/ and b/ prefixes from paths.

        Returns:
            Dict mapping relative file paths to their
            unified diff strings.
        """
        per_file: dict[str, str] = {}

        # Split on diff headers; keep the delimiter
        chunks = re.split(
            r"(?=^diff --git )", full_diff, flags=re.M
        )

        for chunk in chunks:
            chunk = chunk.strip()
            if not chunk.startswith("diff --git"):
                continue

            # Extract file path from diff header
            # Format: diff --git a/path b/path
            header_match = re.match(
                r"diff --git a/(.+?) b/(.+)",
                chunk.split("\n", 1)[0],
            )
            if not header_match:
                continue

            file_path = header_match.group(2).strip()

            # Extract only the hunk content
            # (skip diff/index/--- /+++ headers)
            lines = chunk.split("\n")
            hunk_lines: list[str] = []
            in_hunks = False
            for line in lines:
                if line.startswith("@@"):
                    in_hunks = True
                if in_hunks:
                    hunk_lines.append(line)

            if hunk_lines:
                per_file[file_path] = "\n".join(
                    hunk_lines
                )

        return per_file
