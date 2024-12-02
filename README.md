
# **Software Supply Chain Security**

## **Project Overview**
This project demonstrates the implementation of tools and techniques to enhance software supply chain security. It includes signing, verification, dependency management, code quality improvement, and SBOM generation, aligned with best practices in software development and security.

---

## **Assignments Overview**

### **Assignment 1: Artifact Signing and Verification**
#### Tasks:
1. Created a text file artifact (`artifact.md`) containing the NYU Net ID.
2. Installed Sigstore’s `cosign` tool and signed the artifact, uploading its signature to the Rekor transparency log.
3. Developed Python code to:
   - Fetch entry details from the Rekor log.
   - Extract the signature and certificate.
   - Verify the signature using the public key from the certificate.
   - Verify the inclusion proof of the artifact.
4. Implemented code to check consistency between older and latest checkpoints in the transparency log.

---

### **Assignment 2: Code Quality Improvement**
#### Tasks:
1. **Code Review**:
   - Conducted peer code reviews on GitHub repositories.
   - Created issues linked to specific lines of code for feedback and discussion.
   - Resolved all raised issues in the following week.

2. **Static Analysis Tools**:
   - Used tools to enforce code quality:
     - **Formatting**: Black and Ruff.
     - **Linting**: Flake8, Ruff, and Pylint.
     - **Type Checking**: mypy.
     - **Static Application Security Testing (SAST)**: Bandit.

---

### **Assignment 3: Git Best Practices and Dependency Management**
#### Tasks:
1. **Git Best Practices**:
   - Added the following files to the repository:
     - `README.md` for project documentation.
     - `SECURITY.md` to outline security policies.
     - `CONTRIBUTING.md` for contribution guidelines.
     - `LICENSE` for legal permissions.
     - `CODEOWNERS` to define code ownership.
     - `.gitignore` to exclude unnecessary files.
   - Configured branch protection rules to enforce pull requests for changes to `main`.

2. **Prevent Secrets Leakage**:
   - Configured `trufflehog` and `pre-commit` hooks to scan for secrets in the latest commit.
   - Implemented `pre-commit` hooks for secret detection.

3. **Scrub Old Secrets**:
   - Used `git-filter-repo` to remove sensitive data from repository history.
   - Documented steps in `part3-writeup.txt`.

4. **Build System Configuration**:
   - Used Poetry to manage dependencies via `pyproject.toml`.
   - Configured tools in `pyproject.toml` for code quality:
     - `mypy`
     - `black`
     - `ruff`
     - `flake8`
     - `pylint`
     - `bandit`

5. **Testing and Coverage**:
   - Developed unit tests with at least 10 test cases using `pytest`.
   - Measured code coverage using `pytest-cov` and ensured 75%+ coverage.

---

### **Assignment 4: SBOM Generation and Attestation**
#### Tasks:
1. **Packaging and Publishing**:
   - Packaged the Python project using Poetry.
   - Published the package (`rektor`) on PyPI.
   - Verified the package installation and usage.

2. **SBOM Generation**:
   - Generated a CycloneDX SBOM using `cyclonedx-py` based on the `pyproject.toml`.
   - Saved the SBOM as `cyclonedx-sbom.json`.

3. **Attestation**:
   - Used Sigstore’s `cosign` to attest the SBOM.
   - Generated attestation files:
     - `sbom-attestation.json`
     - `sbom-attestation.bundle`
   - Verified the attestation using `cosign`.

#### Project structure:
````
supply-chain-security/
├── dist/
│   ├── rektor-4.0.0-py3-none-any.whl
│   ├── rektor-4.0.0.tar.gz
│   ├── cyclonedx-sbom.json
│   ├── sbom-attestation.json
│   ├── sbom-attestation.bundle
├── rektor/
│   ├── __init__.py
│   ├── __main__.py
│   ├── main.py
│   └── other_modules.py
├── tests/
│   ├── test_main.py
│   └── other_tests.py
├── pyproject.toml
├── README.md
├── LICENSE
````

---

## **Tools and Technologies**
- **Programming Language**: Python
- **Version Control**: Git (GitHub for repository management)
- **Signing Tool**: Sigstore (`cosign`)
- **Transparency Log**: Rekor
- **Static Analysis Tools**:
  - **Formatting**: Black or Ruff
  - **Linting**: Flake8, Ruff, and Pylint
  - **Type Checking**: mypy
  - **SAST**: Bandit
- **Dependency Management**: Poetry
- **SBOM Tools**: CycloneDX (`cyclonedx-py`)
- **Testing Framework**: pytest with pytest-cov for coverage measurement



## **Future Updates**
This `README` will be updated as new assignments are released or additional tools and techniques are integrated.

---
