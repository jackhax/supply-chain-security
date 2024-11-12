# Software Supply Chain Security

## Project Overview
This project is an implementation of software supply chain security tools and technologies.

## Assignments Overview
The project is divided into the following assignments:

### Assignment 1: Artifact Signing and Verification
#### Tasks
1. Create a text file artifact (`artifact.md`) containing your NYU Net ID.
2. Install Sigstore’s cosign tool and sign the artifact, uploading its signature to the Rekor transparency log.
3. Write Python code to:
   - Fetch entry details from the Rekor log.
   - Extract signature and certificate.
   - Verify the signature using the public key from the certificate.
   - Verify the inclusion proof of the artifact.
4. Implement code to check the consistency between older and latest checkpoints in the transparency log.

### Assignment 2: Code Quality Improvement
#### Tasks
1. **Code Review**:
   - Collaborate with teammates to conduct a code review on their GitHub repositories.
   - Create issues linked to specific lines of code for feedback and discussion.
   - Resolve all raised issues in the following week.
   
2. **Static Analysis Tools**:
   - Black for formatting
   - Flake8, ruff, and pylint for linting
   - mypy for type checking
   - Bandit for SAST (Static Application Security Testing)

### Assignment 3: Git Best Practices and Dependency Management
#### Tasks
1. **Git Best Practices**:
   - Add the following files to the repository:
     - `README.md` for project documentation.
     - `SECURITY.md` to outline security policies.
     - `CONTRIBUTING.md` to guide contributions.
     - `LICENSE` for legal permissions.
     - `CODEOWNERS` to define code ownership.
     - `.gitignore` to exclude unnecessary files.
   - Configure branch protection rules to prevent direct commits to `main` without a pull request.

2. **Prevent Secrets Leakage**:
   - Set up `trufflehog` and `pre-commit` hooks to prevent committing secrets.
   - Configure `pre-commit` to scan only the latest commit for secrets.

3. **Scrub Old Secrets**:
   - Add a `personal.txt` file containing sample data and commit it.
   - Use `git-filter-repo` to remove the file from the repository history.
   - Document the steps in `part3-writeup.txt`.

4. **Build System Configuration**:
   - Set up Poetry for dependency management and create a `pyproject.toml` file.
   - Add tools like mypy, black, ruff, flake8, pylint, and bandit to `pyproject.toml`.

5. **Testing and Coverage**:
   - Add unit tests using `pytest` with at least 10 test cases.
   - Install `pytest-cov` to measure code coverage and ensure at least 75% coverage.

#### More assignments to come

## Tools and Technologies
- **Programming Language**: Python
- **Version Control**: Git (GitHub for repository management)
- **Signing Tool**: Sigstore (cosign)
- **Transparency Log**: Rekor
- **Static Analysis Tools**: Black or Ruff for formatting, Flake8 or Ruff for linting, Bandit for SAST, mypy for type checking
- **Dependency Management**: Poetry
- **Testing Framework**: pytest with pytest-cov for coverage measurement

*Note: This document will be updated as more assignments are released.*
