#!/usr/bin/env python3

import argparse
import html
import pathlib
import re
import subprocess
import sys
import tempfile

import markdown


CSS = """
@page {
  size: Letter;
  margin: 0.7in;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: #1b1f23;
  line-height: 1.55;
  font-size: 12pt;
  max-width: 8.2in;
  margin: 0 auto;
}

h1, h2, h3 {
  line-height: 1.2;
  page-break-after: avoid;
}

h1 {
  font-size: 22pt;
  margin: 0 0 18px 0;
}

h2 {
  font-size: 16pt;
  margin-top: 26px;
}

h3 {
  font-size: 13pt;
  margin-top: 20px;
}

p, li {
  orphans: 3;
  widows: 3;
}

img {
  display: block;
  max-width: 100%;
  margin: 18px auto;
  page-break-inside: avoid;
}

pre {
  background: #f6f8fa;
  border: 1px solid #d0d7de;
  border-radius: 8px;
  padding: 12px;
  overflow-x: auto;
  font-size: 10pt;
}

code {
  font-family: ui-monospace, "SFMono-Regular", Menlo, monospace;
}

blockquote {
  border-left: 4px solid #d0d7de;
  color: #57606a;
  margin: 16px 0;
  padding-left: 14px;
}

ul, ol {
  padding-left: 24px;
}
"""


def absolutize_image_sources(html_text: str, base_dir: pathlib.Path) -> str:
    pattern = re.compile(r'(<img[^>]+src=")([^"]+)(")')

    def repl(match: re.Match[str]) -> str:
        prefix, src, suffix = match.groups()
        if src.startswith(("http://", "https://", "file://", "data:")):
            return match.group(0)
        path = pathlib.Path(src)
        if not path.is_absolute():
            path = (base_dir / path).resolve()
        return f'{prefix}file://{path}{suffix}'

    return pattern.sub(repl, html_text)


def build_html(markdown_text: str, base_dir: pathlib.Path, title: str) -> str:
    body = markdown.markdown(
        markdown_text,
        extensions=["fenced_code", "tables", "sane_lists"],
        output_format="html5",
    )
    body = absolutize_image_sources(body, base_dir)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>{CSS}</style>
</head>
<body>
{body}
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Render markdown to PDF via local Chromium.")
    parser.add_argument("input", help="Input markdown file")
    parser.add_argument("output", help="Output PDF file")
    args = parser.parse_args()

    input_path = pathlib.Path(args.input).resolve()
    output_path = pathlib.Path(args.output).resolve()
    markdown_text = input_path.read_text(encoding="utf-8")
    html_text = build_html(markdown_text, input_path.parent, input_path.stem)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as tmp:
        tmp.write(html_text)
        tmp_path = pathlib.Path(tmp.name)

    script_path = pathlib.Path(__file__).with_name("html_to_pdf.mjs")
    try:
        subprocess.run(
            ["node", str(script_path), str(tmp_path), str(output_path)],
            check=True,
        )
    finally:
        tmp_path.unlink(missing_ok=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
