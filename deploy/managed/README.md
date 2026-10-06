# Managed Keybroker health release

This is the separate health-only service source prepared for review. No installation,
publication, commit or push has occurred. The existing Mac alpha, Bunny tools and ai2
Firefly service retain their own custody, identities and grants.

The [canonical rollout reference](/Volumes/ai-vaults/Core/Context/documentation/keybroker-node-rollout-20261006.md)
owns node evidence, approval gates, update policy and rollback.

- `build.py` hashes the explicit `source-files.json` inputs and the current Git HEAD,
  vets and cross-builds three platforms offline, then pins bootstrap and installer bytes.
- `install.py` is dry-run by default; the reviewed bootstrap copy contains its pin.
- `release-manager.py` accepts fixed approved health metadata and serialises atomic
  upgrades and rollback. It never accepts client URLs, shell commands or credentials.
- The two `test_*.py` files hold synthetic release/installer regressions.

The builder accepts `KEYBROKER_GO` for an explicitly selected installed toolchain;
it does not download a toolchain or dependency. It records whether the hashed source
is committed. Committed-source publication needs its own reviewed build and approval.
Preparation output is retained under `release-preparation/`, outside the source list.
The source identity covers the 36 Go/package inputs. The bootstrap and preparation
receipt separately pin the release manager and frozen installer; they are outside
that source identity.

Only `system.status` is enabled. Signing trust is not enrolled. Future releases need
an approved manifest pin or separately approved signing-key enrolment. Root activation,
Linux service proof, reboot persistence and rollback remain live gates.

```sh
python3 deploy/managed/build.py
python3 -m unittest discover -s deploy/managed -p 'test_*.py'
```
