# Fictional Citizen referendum over the public content service

Citizen `30f1fa9c99f751dbf0a93489fa86d305b02a3021` generated the public proof ZIP and the separate setup with Belenios 3.3.0. The fixture contains three fictional library-hours referenda. It includes only the six public Belenios archives and the Citizen report. The simulator discarded the voter and trustee secrets. The SHA-256 of the ZIP is `e37b90d9573d068696e1d334f2165e21f6cdd5d6351dae32f18c0564dd17e9d1`. The separately retained setup has SHA-256 `6b4c9c2fe3b1ce2ed28d512649aff4cc7e7119e76eaae79898a9df1afeda4ad2`.

The `content-replication` trial hands the public ZIP to the normal contribution service on relay4. A fresh client receives only the owner's public key and the publication name. The reader exports its actual downloaded bytes. After the guest exits, the workflow checks the signed manifest, serving peer, transport observations and byte digest. The Citizen command replays that output with the native Belenios verifier and the separately retained setup in a disconnected namespace.

[Citizen source and replay instructions](https://github.com/VOLPAROSSA/volparossa-citizen/tree/30f1fa9c99f751dbf0a93489fa86d305b02a3021/integrations/belenios)
