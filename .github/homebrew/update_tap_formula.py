"""Generate/update the Razin Homebrew formula file for the tap repository."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from urllib.request import urlopen


PYPI_BASE_URL = "https://pypi.org/pypi"
DEFAULT_PYTHON_FORMULA = "python@3.14"


@dataclass(frozen=True)
class SdistRelease:
    """Represents a Python package source distribution from PyPI."""

    name: str
    version: str
    url: str
    sha256: str


def _load_pypi_json(package: str) -> dict:
    with urlopen(f"{PYPI_BASE_URL}/{package}/json", timeout=30) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def _latest_sdist_release(package: str) -> SdistRelease:
    payload = _load_pypi_json(package)
    version = payload["info"]["version"]
    for artifact in payload.get("urls", []):
        if artifact.get("packagetype") == "sdist":
            return SdistRelease(
                name=package,
                version=version,
                url=artifact["url"],
                sha256=artifact["digests"]["sha256"],
            )
    raise ValueError(f"No sdist artifact found on PyPI for {package}=={version}")


def _render_formula(
    *,
    razin: SdistRelease,
    pyyaml: SdistRelease,
    python_formula: str,
) -> str:
    return f"""class Razin < Formula
  include Language::Python::Virtualenv

  desc "Static analysis scanner for SKILL.md-defined agent skills"
  homepage "https://github.com/theinfosecguy/razin"
  url "{razin.url}"
  sha256 "{razin.sha256}"
  license "MIT"

  depends_on "libyaml"
  depends_on "{python_formula}"

  resource "pyyaml" do
    url "{pyyaml.url}"
    sha256 "{pyyaml.sha256}"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    skill_dir = testpath/"sample"
    skill_dir.mkpath
    (skill_dir/"SKILL.md").write <<~MARKDOWN
      ---
      name: sample-skill
      ---
      # Sample
      command: run-this
    MARKDOWN

    shell_output("#{{bin}}/razin --version")
    system bin/"razin", "scan", "-r", testpath.to_s, "-o", (testpath/"output").to_s, "--no-stdout"
    assert_path_exists testpath/"output"/"sample-skill"/"summary.json"
  end
end
"""


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update Razin Homebrew formula for tap repo")
    parser.add_argument("--output", required=True, type=Path, help="Path to Formula/razin.rb in tap clone")
    parser.add_argument(
        "--python-formula",
        default=DEFAULT_PYTHON_FORMULA,
        help=f'Python formula dependency name (default: "{DEFAULT_PYTHON_FORMULA}")',
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    razin = _latest_sdist_release("razin")
    pyyaml = _latest_sdist_release("PyYAML")
    formula = _render_formula(razin=razin, pyyaml=pyyaml, python_formula=args.python_formula)
    args.output.write_text(formula, encoding="utf-8")
    print(f"Updated {args.output} -> razin {razin.version}, pyyaml {pyyaml.version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
