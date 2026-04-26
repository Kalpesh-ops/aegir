# Contributing to Aegir

Thank you for your interest in contributing.

This is a student-led open-source project in active development, and contributions of all sizes are welcome, including bug reports, documentation improvements, testing feedback, and code changes.

## Ways to Contribute

- Report bugs
- Suggest features or UX improvements
- Improve documentation
- Submit code fixes and enhancements
- Share security and performance feedback

## Before You Start

- Be respectful and constructive in all interactions
- Read our [Code of Conduct](CODE_OF_CONDUCT.md)
- For security issues, follow [SECURITY.md](SECURITY.md) and do not open a public issue

## Reporting Bugs

Open a GitHub Issue and include:

- A clear title and summary
- Steps to reproduce
- Expected behavior and actual behavior
- Screenshots or logs when helpful (redact sensitive data)
- Environment details (OS, Python/Node versions, browser if relevant)

## Requesting Features

Open a GitHub Issue with:

- The problem your feature solves
- Your proposed solution
- Any alternatives considered
- Optional mockups, examples, or references

## Development Workflow

1. Fork the repository.
2. Create a branch from `main`:
	- `feature/short-description` for new features
	- `fix/short-description` for bug fixes
	- `docs/short-description` for documentation updates
3. Make focused changes and write clear commit messages.
4. Run local checks and verify your changes.
5. Open a Pull Request to `main`.

## Pull Request Guidelines

- Keep PRs small and focused
- Explain what changed and why
- Link related issues (for example: `Closes #123`)
- Add screenshots for UI changes when possible
- Update documentation when behavior or setup changes

## Local Setup (Quick Reference)

Backend:

- Install dependencies: `pip install -r requirements.txt`
- Run server: `python server.py`
- Health check: `GET /health`

Frontend:

- `cd frontend`
- Install dependencies: `npm install`
- Start dev server: `npm run dev`
- Lint: `npm run lint`

## Contributor Notes

- Please avoid committing secrets, credentials, or sensitive scan output
- Prefer readable code over clever code
- If unsure about direction, open an issue first and ask

Thanks again for helping improve Aegir.
