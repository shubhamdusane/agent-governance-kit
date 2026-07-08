# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-08

### Added
- Initial release of agent-governance-kit
- `GovernanceLayer` middleware wrapping any agent with policy enforcement
- 10 OWASP Top 10 Agentic AI policies
- PII detection (emails, phones, SSNs, IBANs, Aadhaar, credit cards, IPs)
- Tool call rate limiting and loop detection
- Prompt injection detection
- Memory write validation
- Human escalation thresholds
- EU AI Act compliance logging (Art. 12, 14, 15)
- JSONL violation logging with webhook support
- Comprehensive test suite
- `py.typed` marker for PEP 561
