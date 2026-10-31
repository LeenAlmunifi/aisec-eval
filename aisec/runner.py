"""
runner.py - this is the engine. it actually runs the tests.

what it does: for every probe, every phrasing variant, and however many
repeats I asked for:
    1. send the attack to the model
    2. check the response with the detector (did the attack work?)
    3. save the response + the verdict

then it adds everything up:
    - attack success rate (ASR) = attacks that worked / total attacks
    - block rate = the opposite (1 - ASR)
    - PASS/FAIL = did the block rate hit my threshold?

this is the real pipeline: probe -> model -> detector -> score.
not just making a report, it's doing the actual testing.
"""

from __future__ import annotations

import dataclasses
import time
from typing import List

from .detectors import build_detector
from .probes import Suite
from .provider import OllamaProvider, ProviderError


# one single attempt = one attack sent one time. this just holds the details
# of what happened (what I asked, what came back, did it work)
@dataclasses.dataclass
class AttemptResult:
    probe_id: str
    category: str
    variant: str          # the exact wording I sent
    repeat: int           # which repeat this was (1, 2, 3...)
    response: str         # what the model actually said
    attack_succeeded: bool  # True = attack worked, False = blocked
    error: str = ""       # filled in if the model call failed


# groups all the attempts for ONE probe together, and works out that probe's
# stats. the @property bits are just calculated values (not stored, computed
# on the spot when I ask for them)
@dataclasses.dataclass
class ProbeResult:
    probe_id: str
    category: str
    attempts: List[AttemptResult]

    @property
    def total(self) -> int:
        # how many attempts total for this probe
        return len(self.attempts)

    @property
    def successes(self) -> int:
        # count how many attacks worked
        return sum(1 for a in self.attempts if a.attack_succeeded)

    @property
    def asr(self) -> float:
        # attack success rate = worked / total (guard against divide by zero)
        return self.successes / self.total if self.total else 0.0

    @property
    def block_rate(self) -> float:
        # block rate is just the flip side of ASR
        return 1.0 - self.asr


# the big one: holds results for the WHOLE suite and the overall stats
@dataclasses.dataclass
class SuiteResult:
    suite_name: str
    model: str
    threshold: float
    started_at: str
    probe_results: List[ProbeResult]

    @property
    def total_attempts(self) -> int:
        # add up attempts across all probes
        return sum(pr.total for pr in self.probe_results)

    @property
    def total_successes(self) -> int:
        # add up successful attacks across all probes
        return sum(pr.successes for pr in self.probe_results)

    @property
    def overall_asr(self) -> float:
        # overall attack success rate for the whole run
        t = self.total_attempts
        return self.total_successes / t if t else 0.0

    @property
    def overall_block_rate(self) -> float:
        return 1.0 - self.overall_asr

    @property
    def passed(self) -> bool:
        # the model passes if it blocked at least `threshold` of attacks
        return self.overall_block_rate >= self.threshold


def run_suite(
    suite: Suite,
    provider: OllamaProvider,
    repeats: int = 1,
    verbose: bool = False,
) -> SuiteResult:
    """runs the whole suite and returns all the results added up."""
    probe_results: List[ProbeResult] = []

    # loop through each probe (each attack category)
    for probe in suite.probes:
        # build the right detector for this probe (from the yaml spec)
        detector = build_detector(probe.detector)
        attempts: List[AttemptResult] = []

        # loop through each phrasing, and repeat each one `repeats` times
        for variant in probe.variants:
            for r in range(repeats):
                if verbose:
                    print(f"[{probe.id}] variant={variant!r} repeat={r + 1}/{repeats}")
                try:
                    # send attack to the model, then score the reply
                    response = provider.generate(suite.system_prompt, variant)
                    succeeded = detector.detect(response)
                    err = ""
                except ProviderError as exc:
                    # if the model call fails, record it instead of crashing
                    response, succeeded, err = "", False, str(exc)

                # save this attempt
                attempts.append(
                    AttemptResult(
                        probe_id=probe.id,
                        category=probe.category,
                        variant=variant,
                        repeat=r + 1,
                        response=response,
                        attack_succeeded=succeeded,
                        error=err,
                    )
                )

        # done with this probe, save its grouped results
        probe_results.append(
            ProbeResult(probe_id=probe.id, category=probe.category, attempts=attempts)
        )

    # bundle everything into one result object with a timestamp
    return SuiteResult(
        suite_name=suite.name,
        model=provider.model,
        threshold=suite.threshold,
        started_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        probe_results=probe_results,
    )
