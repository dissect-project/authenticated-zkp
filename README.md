# Verifiable Zero-Knowledge Proofs

Testing ground for verifiable zero-knowledge proofs.

## Examples

- [number](gnark/number/)
    - Verifies if A < B without revealing A
    - Private Inputs:
        - A
    - Public Inputs:
        - B
        - Hash of A
- [age](gnark/age/)
    - Verifies wether an age calculated from a DOB is over a minimum age (over 18, 21, etc.) without revealing the DOB
    - Private Inputs:
        - DOB
    - Public Inputs:
        - Today
        - Minimum Age
        - Hash of DOB

## Execution

Before executing each script, **go** should be installed on the machine. To execute the scripts, run the following command in the directory of the script to execute the respective example without tampering the witness (changing the hash of the private input after computing the proof):

```go
go run . notamper
```

To execute the example with tampering of the witness (change the value of the private input's hash after computing the proof), run the following command:
```go
go run . tamper
```