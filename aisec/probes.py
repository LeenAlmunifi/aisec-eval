"""
probes.py - loads my test cases from the yaml file.

a "probe" = one attack test. it has an id, a category, the detector that
grades it, and a list of variants (different wordings of the same attack).

a "suite" = the whole set: a name, the pass threshold, the hidden system
prompt, and all the probes.

basically this file's job is: read the yaml -> turn it into python objects
the rest of my code can use.
"""

from __future__ import annotations

import dataclasses
from typing import List

import yaml   # library that reads yaml files


# a dataclass is just a simple container. this one holds one probe.
@dataclasses.dataclass
class Probe:
    id: str
    category: str
    detector: dict        # e.g. {type: secret-leak, value: "BLUE-42"}
    variants: List[str]   # the different phrasings of the attack


# this holds the whole suite (all probes + the settings)
@dataclasses.dataclass
class Suite:
    name: str
    threshold: float
    system_prompt: str
    probes: List[Probe]


def load_suite(path: str) -> Suite:
    """reads a yaml file and turns it into a Suite object (with some checks)."""

    # open and parse the yaml file
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    # make sure the file is actually a proper yaml mapping, not junk
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: top level must be a mapping")

    # check the required top-level keys are all there
    for key in ("name", "system_prompt", "probes"):
        if key not in raw:
            raise ValueError(f"{path}: missing required key '{key}'")

    # go through each probe in the file and build a Probe object
    probes = []
    for i, p in enumerate(raw["probes"]):
        # each probe must have these keys or it's broken
        for key in ("id", "detector", "variants"):
            if key not in p:
                raise ValueError(f"{path}: probe #{i} missing '{key}'")
        probes.append(
            Probe(
                id=str(p["id"]),
                category=p.get("category", "uncategorized"),  # default if missing
                detector=p["detector"],
                variants=list(p["variants"]),
            )
        )

    # bundle it all into the Suite object and return it.
    # threshold defaults to 0.70 if I didn't put one in the yaml.
    return Suite(
        name=raw["name"],
        threshold=float(raw.get("threshold", 0.70)),
        system_prompt=raw["system_prompt"],
        probes=probes,
    )
