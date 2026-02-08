# NOSP Development Guide

For developers who want to contribute to or extend NOSP.

---

## Development Environment Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
cd NOSP
```

### 2. Install Development Tools

```powershell
# Install Python dev dependencies
pip install -e ".[dev]"

# Install Rust tools
cargo install cargo-watch
cargo install cargo-edit

# Install code formatters
pip install black isort
cargo install rustfmt
```

### 3. IDE Setup

#### VS Code (Recommended)
Install extensions:
- Python (Microsoft)
- Rust Analyzer
- Even Better TOML
- GitLens

#### PyCharm
- Enable Rust plugin
- Configure Python interpreter
- Set up code style

---

## Project Structure Explained

```
NOSP/
├── src/                      # Rust source code
│   └── lib.rs               # Main Rust module
│
├── python/nosp/             # Python package
│   ├── __init__.py         # Package init
│   ├── database.py         # Database layer
│   ├── ai_engine.py        # AI integration
│   └── risk_scorer.py      # Risk assessment
│
├── main.py                  # Streamlit app
├── Cargo.toml              # Rust config
├── pyproject.toml          # Python config
└── requirements.txt        # Dependencies
```

---

## Development Workflow

### 1. Building for Development

```powershell
# Build Rust module in debug mode
maturin develop

# Build in release mode (slower build, faster execution)
maturin develop --release
```

### 2. Running with Hot Reload

```powershell
# Terminal 1: Watch Rust changes
cargo watch -x "build"

# Terminal 2: Run Streamlit with auto-reload
streamlit run main.py --server.runOnSave true
```

### 3. Making Changes

#### Python Changes
1. Edit Python files
2. Streamlit will auto-reload
3. Test in browser

#### Rust Changes
1. Edit `src/lib.rs`
2. Run `maturin develop`
3. Restart Streamlit

---

## Code Style Guidelines

### Python
```python
# Use type hints
def function_name(param: str, optional: Optional[int] = None) -> bool:
    """
    Docstring explaining the function.
    
    Args:
        param: Description
        optional: Description
        
    Returns:
        Description
    """
    pass

# Format with black
# Sort imports with isort
```

### Rust
```rust
// Use descriptive names
fn descriptive_function_name(parameter: &str) -> Result<String, Error> {
    // Comments for complex logic
    Ok(parameter.to_string())
}

// Format with rustfmt
// Document public APIs
```

---

## Testing

### Python Tests

```python
# tests/test_database.py
import pytest
from nosp.database import NOSPDatabase

def test_database_initialization():
    db = NOSPDatabase(":memory:")
    assert db.conn is not None

def test_event_insertion():
    db = NOSPDatabase(":memory:")
    event = {
        'event_id': 1,
        'process_guid': '{12345}',
        # ... more fields
    }
    event_id = db.insert_event(event, 50)
    assert event_id is not None
```

Run tests:
```powershell
pytest tests/
```

### Rust Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_parsing() {
        let xml = "<Event>...</Event>";
        let result = parse_event_data(xml);
        assert!(result.is_ok());
    }
}
```

Run tests:
```powershell
cargo test
```

---

## Adding New Features

### Adding a New Risk Factor

1. Edit `python/nosp/risk_scorer.py`:

```python
class RiskScorer:
    NEW_PATTERN = {
        r'suspicious-pattern': 30,
    }
    
    def calculate_risk(self, event):
        # ... existing code ...
        
        # Add new check
        new_score = self._check_new_pattern(event)
        if new_score > 0:
            risk_factors.append(('new_pattern', new_score, 'Description'))
            total_score += new_score
```

2. Test the new pattern
3. Update documentation

### Adding a New Event Type

1. Edit `src/lib.rs`:

```rust
#[pyfunction]
fn get_sysmon_network_events(py: Python) -> PyResult<Vec<PyObject>> {
    // Query Event ID 3 (Network Connection)
    let query = w!("*[System[(EventID=3)]]");
    // ... implementation
}
```

2. Update Python module
3. Expose new function

### Adding UI Components

1. Edit `main.py`:

```python
def render_new_tab():
    st.markdown("### New Feature")
    # Add components
    
# Add to tabs
tab1, tab2, tab3, tab4 = st.tabs([...])
with tab4:
    render_new_tab()
```

---

## Performance Profiling

### Python Profiling

```python
import cProfile
import pstats

profiler = cProfile.Profile()
profiler.enable()

# Code to profile

profiler.disable()
stats = pstats.Stats(profiler)
stats.sort_stats('cumtime')
stats.print_stats(20)
```

### Rust Profiling

```powershell
# Install cargo flamegraph
cargo install flamegraph

# Profile
cargo flamegraph --bin nosp_core
```

---

## Debugging

### Python Debugging

```python
# Add breakpoints
import pdb; pdb.set_trace()

# Or use VS Code debugger
# launch.json configuration
```

### Rust Debugging

```powershell
# Build with debug info
cargo build

# Use VS Code debugger with CodeLLDB extension
```

### Logging

```python
import logging
logger = logging.getLogger(__name__)
logger.debug("Debug message")
logger.info("Info message")
logger.warning("Warning message")
logger.error("Error message")
```

---

## Release Process

### 1. Version Bump

```toml
# Cargo.toml
[package]
version = "0.2.0"

# pyproject.toml
[project]
version = "0.2.0"
```

### 2. Build Release

```powershell
# Build optimized Rust module
maturin build --release

# Create Python wheel
python -m build
```

### 3. Test Release

```powershell
# Install in clean environment
python -m venv test_env
test_env\Scripts\activate
pip install dist/nosp-0.2.0-*.whl

# Test functionality
run_nosp.bat
```

### 4. Create Release

```bash
git tag v0.2.0
git push origin v0.2.0
```

---

## Contributing Guidelines

### 1. Fork & Branch

```bash
git checkout -b feature/new-feature
```

### 2. Make Changes

- Follow code style guidelines
- Add tests
- Update documentation

### 3. Commit

```bash
git commit -m "feat: Add new feature"
```

Use conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `refactor:` Code refactoring
- `test:` Tests
- `chore:` Maintenance

### 4. Pull Request

- Clear description
- Reference issues
- Include tests
- Update CHANGELOG

---

## Common Development Tasks

### Regenerate Requirements

```powershell
pip freeze > requirements.txt
```

### Clean Build

```powershell
# Clean Python artifacts
Remove-Item -Recurse -Force __pycache__, *.pyc, *.pyo

# Clean Rust artifacts
cargo clean

# Clean built modules
Remove-Item -Recurse -Force target/, dist/, *.egg-info/
```

### Database Schema Changes

```python
def migrate_database():
    cursor = db.conn.cursor()
    cursor.execute("""
        ALTER TABLE events 
        ADD COLUMN new_column TEXT
    """)
    db.conn.commit()
```

---

## Resources

### Documentation
- [Rust Book](https://doc.rust-lang.org/book/)
- [PyO3 Guide](https://pyo3.rs/)
- [Streamlit Docs](https://docs.streamlit.io/)
- [Ollama Docs](https://github.com/ollama/ollama)

### Tools
- [Maturin](https://github.com/PyO3/maturin)
- [Windows Crate](https://github.com/microsoft/windows-rs)
- [pytest](https://pytest.org/)

---

## Getting Help

- Check [TECHNICAL_DOCS.md](TECHNICAL_DOCS.md)
- Review existing code
- Ask in discussions
- Open issues for bugs

---

**Happy coding! 🚀**
