# Contributing to RoleFlux

First off, thank you for considering contributing to RoleFlux! It's people like you that make RoleFlux a powerful, community-driven Cloud Detection & Response platform.

## How Can I Contribute?

### 1. Reporting Bugs
If you find a false positive, a broken integration, or a bug in the Next.js UI, please open an issue!
* Use the **Bug Report** template.
* Include detailed steps to reproduce.
* Provide logs (scrubbed of any sensitive IAM emails or project IDs).

### 2. Suggesting Enhancements
Have an idea for a new detection rule, a new cloud provider (AWS/Azure), or a UI feature?
* Use the **Feature Request** template.
* Explain the security value of the feature (e.g., "This detects lateral movement via X").

### 3. Pull Requests
1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests to `tests/test_detection.py`.
3. Ensure the test suite passes (`pytest tests/`).
4. Format your Python code according to PEP8 guidelines (we use `flake8`).
5. Issue that pull request!

## Local Development Setup

To test the detection engine locally without deploying to GCP:

1. Run the bootstrap script:
   ```bash
   ./setup.sh
   ```
2. Activate the virtual environment:
   ```bash
   source venv/bin/activate
   ```
3. Run the Purple Team Attack Simulator:
   ```bash
   python3 attack-simulator/run_simulation.py
   ```
   *(This script generates mock GCP Audit Logs and feeds them directly into the deterministic Python engine for testing).*

## Code of Conduct
By participating in this project, you agree to maintain a respectful and welcoming environment for everyone. We do not tolerate harassment of any kind.

Happy hunting! 🛡️
