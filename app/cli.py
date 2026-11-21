"""Demo without a server: python -m app.cli fixtures/incident_high.json"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from . import llm
from .xdr import normalise, recommend

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else FIXTURES / "incident_high.json"
    incident = normalise(json.loads(path.read_text()))
    recommendation = recommend(incident)
    summary = llm.build_summary(incident, recommendation)
    json.dump(
        {
            "incident": incident.as_dict(),
            "recommendation": recommendation,
            "summary": summary["text"],
            "summary_source": summary["source"],
        },
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
