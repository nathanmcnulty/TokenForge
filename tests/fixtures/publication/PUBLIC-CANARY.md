# Public synthetic canary

`public-canary/` contains the existing publication fixture's seven-file candidate:
invented clients, empty observations, one in-flight unknown cell and one unknown
matrix. It deliberately represents incomplete worker coverage. It contains no
collector output, account/tenant metadata, permission inventory or credentials.
The repeated evidence hashes are invented fixture values, not live receipts.

The manual compatibility probe updates only source/run/attempt in its manifest.
Its artifact is explicitly named synthetic. This tests GitHub artifact transport;
it does not establish production approval, protected-main policy or live collection.
