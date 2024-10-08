# Software Supply Chain Security Project

## Project Overview
This project is an implementation of a software supply chain security tools and technologies.

## Assignments Overview
The project will be divided into the following assignments:

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
   - Flake8, ruff and pylint for linting
   - mypy for Type checking
   - Bandit for SAST

#### More assignments to come

## Tools and Technologies
- **Programming Language**: Python
- **Version Control**: Git (GitHub for repository management)
- **Signing Tool**: Sigstore (cosign)
- **Transparency Log**: Rekor
- **Static Analysis Tools**: Black or RUFF for formatting, Flake8 or RUFF for lining, Bandit for SAST, mypy for Type checking

*Note: This document will be updated as more assignments are released.*
