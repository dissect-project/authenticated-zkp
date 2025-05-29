# Verifiable Zero-Knowledge Proofs

Testing ground for verifiable zero-knowledge proofs.

## Examples

- [number](number/)
    - Verifies if A < B without revealing A
    - Private Inputs:
        - A
    - Public Inputs:
        - B
        - Hash of A
- [age](age/)
    - Verifies wether an age calculated from a DOB is over a minimum age (over 18, 21, etc.) without revealing the DOB
    - Private Inputs:
        - DOB
    - Public Inputs:
        - Today
        - Minimum Age
        - Hash of DOB