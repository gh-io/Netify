from pathlib import Path
from jinja2 import Template

HEADER_TEMPLATE = Path("tools/license_header.j2").read_text()

CONFIG = {
    "project_name": "KubuCore",
    "version": "0.1.0",
    "repo_url": "https://github.com/yourname/kubucore",
    "copyright_lines": [
        "Copyright (c) 2025 Seriki Yakub",
        "Copyright (c) 2025 Contributors",
    ],
    "spdx_expressions": ["MIT"],
}

TARGET_EXTENSIONS = {".c", ".cpp", ".h", ".hpp", ".rs"}

def apply_header(file_path: Path):
    content = file_path.read_text()

    if "SPDX-License-Identifier" in content:
        return  # already licensed

    header = Template(HEADER_TEMPLATE).render(**CONFIG)
    file_path.write_text(header + "\n\n" + content)

def main():
    for path in Path(".").rglob("*"):
        if path.suffix in TARGET_EXTENSIONS:
            apply_header(path)

if __name__ == "__main__":
    main()
