"""
aisec-eval - my AI security evaluation tool.

this file marks the "aisec" folder as a python package so I can import from
it (like "from aisec.detectors import ...").

what the tool does: it sends attack prompts to a local model (through Ollama),
grades the answers with detectors, and writes html/json reports. it measures
whether the model HOLDS a security boundary - it does not try to pull out any
actual harmful content.

the three things I test for:
  - secret / system-prompt leaking
  - prompt injection (model following injected instructions)
  - refusal consistency (does it refuse off-topic stuff like it should)
"""

# the version number of my tool, used by the --version command
__version__ = "0.1.0"
