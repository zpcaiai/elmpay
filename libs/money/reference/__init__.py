"""Executable specification of the money model (B09).

This is the *reference implementation*: pure integer arithmetic over minor
units, no floating point anywhere. Language implementations (Java first) must
reproduce it exactly, and ``contracts/money/vectors.json`` — generated from
this code — is the conformance suite they are held to.
"""
