# Contributing to NOSP

🎉 First off, thank you for considering contributing to NOSP! 🎉

NOSP is built by the community, for the community. Every contribution helps make security monitoring better for everyone.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)

---

## 📜 Code of Conduct

### Our Pledge

We pledge to make participation in NOSP a harassment-free experience for everyone, regardless of:
- Age, body size, disability, ethnicity, gender identity
- Level of experience, education, socio-economic status
- Nationality, personal appearance, race, religion
- Sexual identity and orientation

### Our Standards

**Positive behavior includes:**
- ✅ Using welcoming and inclusive language
- ✅ Being respectful of differing viewpoints
- ✅ Accepting constructive criticism gracefully
- ✅ Focusing on what's best for the community
- ✅ Showing empathy towards others

**Unacceptable behavior includes:**
- ❌ Trolling, insulting/derogatory comments, personal attacks
- ❌ Public or private harassment
- ❌ Publishing others' private information
- ❌ Unprofessional conduct

---

## 🤝 How Can I Contribute?

### Reporting Bugs

**Before submitting:**
1. Check [existing issues](https://github.com/4fqr/nosp/issues)
2. Update to the latest version
3. Check [FAQ.md](FAQ.md) for common problems

**Good bug reports include:**
- Clear, descriptive title
- Steps to reproduce
- Expected vs actual behavior
- NOSP version, OS, Python/Rust versions
- Relevant logs (sanitize sensitive data!)

**Example:**
```markdown
### Bug: Process tree visualization crashes with > 1000 nodes

**Environment:**
- NOSP: v1.0.0-apex
- OS: Windows 11 Pro (Build 22621)
- Python: 3.11.5
- Rust: 1.72.0

**Steps to Reproduce:**
1. Start monitoring
2. Let run for 2+ hours (collecting ~1500 processes)
3. Navigate to "Process Tree" tab
4. Application freezes

**Expected:** Tree renders with pagination
**Actual:** Application becomes unresponsive

**Logs:**
```
[ERROR] Memory allocation failed: process_tree.py:145
```
```

### Suggesting Enhancements

We love new ideas! **Before suggesting:**
1. Check [roadmap in README](README.md#roadmap)
2. Search existing feature requests
3. Consider if it fits NOSP's mission

**Good enhancement requests include:**
- Clear use case explanation
- Why existing features don't solve it
- Implementation suggestions (optional)
- Willingness to contribute code (awesome!)

### Your First Code Contribution

**Great starting points:**
- Issues labeled `good first issue`
- Issues labeled `help wanted`
- Documentation improvements
- Test coverage increases

### Pull Requests

We actively welcome pull requests!

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. If you've changed APIs, update the documentation
4. Ensure the test suite passes
5. Make sure your code follows our style guidelines
6. Issue that pull request!

---

## 🛠️ Development Setup

### Prerequisites

```bash
# Required
- Python 3.8+
- Rust 1.70+
- Git

# Optional (for full development)
- Docker
- VS Code with extensions:
  - Python
  - rust-analyzer
  - GitLens
```

### Setup Steps

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/nosp.git
cd nosp

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# 3. Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 4. Install pre-commit hooks
pip install pre-commit
pre-commit install

# 5. Build Rust core
maturin develop

# 6. Run tests to verify setup
pytest tests/ -v
cargo test
```

### Development Workflow

```bash
# Create feature branch
git checkout -b feature/amazing-detection

# Make changes, test frequently
pytest tests/ -k test_related_to_your_change
cargo test

# Check code quality
black python/
flake8 python/
mypy python/nosp/
cargo fmt
cargo clippy

# Commit (pre-commit hooks will run)
git add .
git commit -m "feat: add amazing detection for X"

# Push and create PR
git push origin feature/amazing-detection
```

---

## 📏 Coding Standards

### Python Style Guide

We follow **PEP 8** with some modifications:

```python
# Line length: 100 characters (not 79)
# Use Black for auto-formatting

# Good: Clear function names, type hints, docstrings
def calculate_risk_score(event: Dict[str, Any], threshold: int = 50) -> int:
    """
    Calculate risk score for a security event.
    
    Args:
        event: Security event dictionary
        threshold: Minimum score threshold
        
    Returns:
        Risk score (0-100)
    """
    score = analyze_event(event)
    return max(score, threshold)

# Bad: No types, unclear naming, missing docs
def calc(e, t=50):
    s = analyze(e)
    return max(s, t)
```

**Python Best Practices:**
- ✅ Type hints for all function signatures
- ✅ Docstrings for public functions/classes
- ✅ Use `pathlib.Path` over `os.path`
- ✅ F-strings for formatting
- ✅ Explicit is better than implicit
- ❌ Don't use bare `except:`
- ❌ Don't use mutable default arguments

### Rust Style Guide

We follow `rustfmt` defaults:

```rust
// Good: Clear naming, error handling, comments
/// Calculate SHA-256 hash of file
pub fn calculate_file_hash(path: String) -> Result<String, String> {
    let file = File::open(&path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    // Implementation...
    Ok(hash)
}

// Bad: Poor error handling, no docs
pub fn calc_hash(p: String) -> String {
    let f = File::open(&p).unwrap();  // NEVER unwrap in production!
    // ...
}
```

**Rust Best Practices:**
- ✅ Use `Result<T, E>` for fallible operations
- ✅ Proper error propagation with `?`
- ✅ Document public APIs with `///`
- ✅ Run `cargo clippy` and fix warnings
- ❌ Don't use `unwrap()` or `expect()` in production code
- ❌ Don't ignore clippy warnings

### Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/):

```bash
# Format: <type>(<scope>): <description>

# Types:
feat: New feature (e.g., "feat(rules): add regex support")
fix: Bug fix (e.g., "fix(ui): resolve table rendering issue")
docs: Documentation only (e.g., "docs: update installation guide")
style: Code style changes (formatting, no logic change)
refactor: Code refactoring (no behavior change)
perf: Performance improvement
test: Adding/updating tests
chore: Maintenance tasks (dependencies, build, etc.)

# Examples:
feat(ml): implement isolation forest anomaly detection
fix(terminal): sanitize command injection attempts
docs(api): add docstrings to RiskScorer class
test(integration): add end-to-end process tree test
```

---

## 🧪 Testing Guidelines

### Test Coverage Requirements

- **New features:** 100% coverage required
- **Existing code:** Minimum 80% coverage
- **Critical paths:** 100% coverage (auth, command execution, file operations)

### Writing Tests

```python
# Good test: Descriptive name, clear setup, single concern
def test_risk_scorer_detects_suspicious_powershell_command():
    """Risk scorer should flag encoded PowerShell commands."""
    # Arrange
    scorer = RiskScorer()
    event = {
        "image": "powershell.exe",
        "command_line": "powershell.exe -enc SGVsbG8gV29ybGQ="
    }
    
    # Act
    score = scorer.calculate_risk(event)
    
    # Assert
    assert score >= 75, "Encoded PowerShell should be high risk"
    assert scorer.get_risk_level(score) == "HIGH"

# Bad test: Vague name, multiple concerns, unclear
def test_scorer():
    s = RiskScorer()
    e = {"image": "powershell.exe"}
    assert s.calculate_risk(e) > 0
    assert s.another_method() == True  # Testing multiple things!
```

### Running Tests

```bash
# Python tests
pytest tests/ -v                          # All tests
pytest tests/test_risk_scorer.py         # Specific file
pytest tests/ -k "test_powershell"       # By pattern
pytest tests/ --cov=python/nosp          # With coverage

# Rust tests
cargo test                                # All tests
cargo test --test integration_tests      # Integration tests
cargo test calculate_hash                # By name

# Run all tests (CI simulation)
pytest tests/ --cov=python/nosp && cargo test
```

---

##📚 Documentation

### Documentation is Code!

All documentation should be:
- ✅ Clear and concise
- ✅ Updated with code changes
- ✅ Include code examples
- ✅ Spell-checked (use Grammarly/LanguageTool)

### Docstring Format (Python)

```python
def detect_threat(event: Dict[str, Any], model: str = "llama3") -> Dict[str, Any]:
    """
    Analyze security event using AI model.
    
    This function sends the event to Ollama for LLM-based threat analysis,
    including MITRE ATT&CK technique identification.
    
    Args:
        event: Security event dictionary with keys:
            - image: Process image path (str)
            - command_line: Full command line (str)
            - user: User account name (str)
        model: Ollama model name (default: "llama3")
    
    Returns:
        Dictionary with analysis results:
            - threat_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
            - mitre_tactic: MITRE ATT&CK tactic (str)
            - mitre_technique: MITRE ATT&CK technique ID (str)
            - description: Human-readable analysis (str)
    
    Raises:
        ConnectionError: If Ollama server is unreachable
        ValueError: If event is missing required fields
    
    Example:
        >>> event = {
        ...     "image": "powershell.exe",
        ...     "command_line": "powershell.exe -enc ...",
        ...     "user": "SYSTEM"
        ... }
        >>> result = detect_threat(event)
        >>> print(result["threat_level"])
        'HIGH'
    """
```

### API Documentation

When adding/changing APIs:
1. Update [API_REFERENCE.md](API_REFERENCE.md)
2. Add code examples
3. Document breaking changes in [CHANGELOG.md](CHANGELOG.md)

---

## 🎯 Specific Contribution Areas

### 🔌 Adding Detection Rules

```yaml
# rules.yaml
rules:
  - name: "Your Detection Rule"
    description: "What it detects"
    severity: "high"
    enabled: true
    conditions:
      - field: "image"
        operator: "contains"
        value: "suspicious.exe"
    actions:
      - type: "alert"
        priority: "high"
```

Then add tests:
```python
def test_custom_rule_detects_suspicious_exe():
    engine = RulesEngine("rules.yaml")
    event = {"image": "suspicious.exe"}
    matches = engine.evaluate_rules(event)
    assert len(matches) > 0
```

### 🧩 Developing Plugins

```python
# plugins/my_plugin.py
from nosp.plugin_manager import Plugin

class MyPlugin(Plugin):
    """Plugin description."""
    
    def __init__(self):
        super().__init__(name="my_plugin", version="1.0.0")
    
    def on_event(self, event):
        """Process event."""
        if self.is_suspicious(event):
            self.alert("Suspicious activity detected!")
    
    def is_suspicious(self, event) -> bool:
        """Your detection logic."""
        return event.get("risk_score", 0) > 80
```

---

## 🏆 Recognition

Contributors will be:
- ✅ Listed in [README.md contributors section](README.md#acknowledgments)
- ✅ Added to GitHub contributors graph
- ✅ Mentioned in [CHANGELOG.md](CHANGELOG.md) for major contributions
- ✅ Invited to join NOSP Discord with "Contributor" role

---

## 📞 Questions?

- 💬 **Discord**: [Join NullSec Community](https://dsc.gg/nullsec)
- 📧 **Email**: 4fqr5@atomicmail.io
- 💡 **Discussions**: [GitHub Discussions](https://github.com/4fqr/nosp/discussions)

---

**Thank you for making NOSP better! 🎉**

Together, we're building the future of security monitoring.

[⬆ Back to Top](#contributing-to-nosp)
