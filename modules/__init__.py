"""modules package (PurpleLab)

This package contains the functional building blocks used by purplelab.py:
- setup      : installation + configuration of sensors and Ollama runtime
- emulation  : scenario generation + safe attack emulation
- collector  : telemetry collection + normalization into a timeline
- ai_analyzer: LLM-based SOC analysis, IOC extraction, rule drafting (Ollama)
- reporter   : report generation

Keeping these separated makes the project easier to test and extend.
"""

from . import setup, emulation, collector, ai_analyzer, reporter
