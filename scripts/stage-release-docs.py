#!/usr/bin/env python3
"""Stage and verify the complete offline operations documentation closure."""

import argparse
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import sys
from urllib.parse import unquote, urlsplit


DOCUMENTS = (
    "docs/operations.md",
    "docs/offline-upgrades.md",
    "docs/platform-setup.md",
)
MAX_FILES = 256
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
INLINE_LINK = re.compile(r"!?\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^\s)]+)(?:\s+[\"'][^\n]*[\"'])?\s*\)")
DEFINITION = re.compile(r"^ {0,3}\[([^\]]+)\]:\s*(<[^>\n]+>|\S+)(?:\s+[\"'][^\n]*[\"'])?\s*$")
REFERENCE = re.compile(r"!?\[([^\]\n]+)\]\[([^\]\n]*)\]")


def prose(text, inline_code=True):
    """Ignore fenced examples and inline code, which are not navigable links."""
    result = []
    fence = None
    for line in text.splitlines():
        match = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if match:
            marker = match[1]
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence) and not match[2].strip():
                fence = None
            continue
        if fence is None:
            result.append(re.sub(r"(`+).*?\1", "", line) if inline_code else line)
    if fence is not None:
        raise ValueError("unclosed Markdown fence")
    return "\n".join(result)


def links(text):
    text = prose(text)
    definitions = {}
    for line in text.splitlines():
        match = DEFINITION.fullmatch(line)
        if match:
            label = " ".join(match[1].split()).casefold()
            if label in definitions:
                raise ValueError("duplicate Markdown reference definition")
            definitions[label] = match[2].strip("<>")
    result = [match[1].strip("<>") for match in INLINE_LINK.finditer(text)]
    for match in REFERENCE.finditer(text):
        label = " ".join((match[2] or match[1]).split()).casefold()
        if label not in definitions:
            raise ValueError("undefined Markdown link reference")
        result.append(definitions[label])
    # Shortcut reference links are resolved only by an actual definition.
    for match in re.finditer(r"!?\[([^\]\n]+)\](?![\[(])", text):
        label = " ".join(match[1].split()).casefold()
        if label in definitions:
            result.append(definitions[label])
    return result


def anchors(text):
    result = set()
    counts = {}
    for line in prose(text, inline_code=False).splitlines():
        match = re.match(r"^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$", line)
        if not match:
            continue
        title = re.sub(r"[^\w\- ]", "", match[1].lower()).replace(" ", "-")
        count = counts.get(title, 0)
        counts[title] = count + 1
        result.add(title if count == 0 else f"{title}-{count}")
    return result


def local_target(document, destination):
    parsed = urlsplit(destination)
    if parsed.scheme:
        if parsed.scheme not in {"https", "http", "mailto"}:
            raise ValueError("unsupported documentation URL scheme")
        return None
    if parsed.netloc or parsed.query:
        raise ValueError("ambiguous local documentation URL")
    path = unquote(parsed.path)
    if "\\" in path or "\0" in path or path.startswith("/"):
        raise ValueError("unsafe local documentation path")
    relative = posixpath.normpath(posixpath.join(str(PurePosixPath(document).parent), path)) if path else document
    parts = PurePosixPath(relative).parts
    if relative == ".." or relative.startswith("../") or any(part.startswith(".") for part in parts):
        raise ValueError("documentation reference escapes its release tree")
    return relative, unquote(parsed.fragment)


def read_file(root, relative):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("documentation root must be a real directory")
    path = root
    for part in PurePosixPath(relative).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("linked documentation inputs are not accepted")
    if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"missing, nonregular or oversized documentation input: {relative}")
    return path.read_bytes()


def closure(root, seeds, supplied=None):
    supplied = supplied or {}
    pending = list(seeds)
    files = {}
    total = 0
    while pending:
        relative = pending.pop()
        if relative in files:
            continue
        content = supplied.get(relative)
        if content is None:
            content = read_file(root, relative)
        files[relative] = content
        total += len(content)
        if len(files) > MAX_FILES or len(content) > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
            raise ValueError("offline documentation exceeds its release budget")
        if relative.endswith(".md"):
            for destination in links(content.decode("utf-8")):
                target = local_target(relative, destination)
                if target is not None:
                    pending.append(target[0])
    for relative, content in files.items():
        if not relative.endswith(".md"):
            continue
        for destination in links(content.decode("utf-8")):
            target = local_target(relative, destination)
            if target is not None and target[1]:
                name, fragment = target
                if not name.endswith(".md") or fragment not in anchors(files[name].decode("utf-8")):
                    raise ValueError(f"missing offline documentation anchor: {relative} -> {destination}")
    return files


def entry_documents(version):
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        raise ValueError("release documentation needs an exact software version")
    return {
        "README.md": (
            f"# xssc {version}\n\n"
            "Linux AMD64 GNU 升级与恢复工具。由 XSSI 脚本下载并校验发行包后，控制并停止全部持久状态写入服务，再执行离线维护。\n\n"
            "- [操作、恢复和发行条件](docs/operations.md)\n"
            "- [经 SHA-256 校验发行物的完整升级合同](docs/offline-upgrades.md)\n"
            "- [Linux 安装、诊断和卸载](docs/platform-setup.md)\n\n"
            "程序为 `bin/xssc`；产品安装、包生成及自动升级脚本由独立 XSSI 仓库交付。"
            "`share/package.json` 声明程序、文档和其余发行文件的完整库存；"
            "`share/package.sha256` 为该清单的 SHA256 摘要。归档另附 `.sha256` 校验文件。\n"
        ).encode(),
        "OFFLINE-UPGRADES.md": (
            "# 离线升级说明入口\n\n"
            "完整字段、校验和恢复条件见[经 SHA-256 校验的离线升级合同](docs/offline-upgrades.md)。\n\n"
            "安装、诊断和卸载见[部署指南](docs/platform-setup.md)。\n"
        ).encode(),
    }


def stage(source, package, version):
    if source.is_symlink() or package.is_symlink():
        raise ValueError("documentation roots cannot be symbolic links")
    source = source.resolve(strict=True)
    package = package.resolve(strict=True)
    entry = entry_documents(version)
    files = closure(source, DOCUMENTS + tuple(entry), entry)
    # Check every destination before writing; no source or prior package files
    # are replaced when the documentation closure is incomplete.
    for relative in files:
        path = package / relative
        if path.exists() or path.is_symlink():
            raise ValueError("release documentation destination already exists")
        for parent in path.parents:
            if parent == package:
                break
            if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
                raise ValueError("unsafe release documentation parent")
    for relative, content in sorted(files.items()):
        path = package / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        with path.open("xb") as output:
            output.write(content)
        os.chmod(path, 0o644)
    return verify(package, version)


def verify(package, version):
    expected_entries = entry_documents(version)
    for relative, expected in expected_entries.items():
        if read_file(package, relative) != expected:
            raise ValueError("release documentation entry/version differs")
    return closure(package, DOCUMENTS + tuple(expected_entries))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["stage", "verify"])
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    if args.operation == "stage":
        if args.source_root is None:
            parser.error("stage requires --source-root")
        files = stage(args.source_root, args.package_root, args.version)
    else:
        files = verify(args.package_root, args.version)
    print(f"Offline release documentation closure: {len(files)} files verified")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError) as error:
        print(f"release documentation validation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
