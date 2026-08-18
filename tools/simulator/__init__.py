"""Offline provider simulators for the local development platform (B04).

Standard library only: the simulators must start on a developer laptop and in
an air-gapped CI agent without a package index. They serve *synthetic* data
only and refuse to start if handed anything that looks like a production
credential (NN-07) or card data (NN-02).
"""
