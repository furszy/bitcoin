Wallet
======

Migrating Legacy Wallets to Descriptor Wallets
---------------------------------------------

An experimental RPC `migratewallet` has been added to migrate Legacy (non-descriptor) wallets to
Descriptor wallets. Migrated wallets will have all of their addresses and private keys added to
a newly created Descriptor wallet that has the same name as the original wallet. Because Descriptor
wallets do not support having private keys and watch-only scripts, there may be up to two
additional wallets created after migration. In addition to a descriptor wallet of the same name,
there may also be a wallet named `<name>_watchonly` and `<name>_solvables`. `<name>_watchonly`
contains all of the watchonly scripts. `<name>_solvables` contains any scripts which the wallet
knows the but is not watching the corresponding P2(W)SH scripts.

Migrated wallets will also generate new addresses differently. While the same BIP 32 seed will be
used, the BIP 44, 49, 84, and 86 standard derivation paths will be used. After migrating, a new
backup of the wallet(s) will need to be created.

Given that there is an extremely large number of possible configurations for the scripts that
Legacy wallets can know about, be watching for, and be able to sign for, `migratewallet` only
makes a best effort attempt to capture all of these things into Descriptor wallets. There may be
unforseen configurations which result in some scripts being excluded. If a migration fails
unexpectedly or otherwise misses any scripts, please create an issue on GitHub. A backup of the
original wallet can be found in the wallet directory with the name `<name>-<timestamp>.legacy.bak`.
