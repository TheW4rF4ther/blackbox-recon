# Contributing to Blackbox Recon

Thank you for your interest in contributing to Blackbox Recon! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and professional
- Focus on constructive feedback
- Respect the security-sensitive nature of this tool

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- A clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version, etc.)

### Suggesting Features

We welcome feature suggestions! Please open an issue with:
- A clear description of the feature
- Use cases and benefits
- Any implementation ideas you have

### Pull Requests

1. Fork the repository
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests if applicable
5. Update documentation
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to your fork (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/blackbox-recon.git
cd blackbox-recon

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
black src/
flake8 src/
mypy src/
```

### Coding Standards

- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Write docstrings for functions and classes
- Keep functions focused and modular
- Add comments for complex logic

### Testing

- Write tests for new features
- Ensure all tests pass before submitting PR
- Aim for good test coverage

### Documentation

- Update README.md if adding new features
- Add docstrings to new functions/classes
- Update examples/ if adding new configuration options

## Security Considerations

Given the nature of this tool:
- Never submit code that performs unauthorized testing
- Ensure all features require explicit user intent
- Do not add automatic exploitation capabilities
- Focus on reconnaissance and analysis, not exploitation

## Areas for Contribution

We especially welcome contributions in:
- New reconnaissance modules
- Additional AI provider integrations
- Output format improvements
- Performance optimizations
- Bug fixes
- Documentation improvements
- Test coverage

## Questions?

Feel free to open an issue for any questions about contributing.

Thank you for helping make Blackbox Recon better!
