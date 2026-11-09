# Agent CI inputs

This Rust binary prepares the public native provider selected by a reviewed
`provider.lock.json`. Run it only on execution hosts or runners. It does not
install or start the provider. The runtime agent remains a separate package.

`fetch-provider SPEC DESTINATION` consumes the existing provider lock.
`fetch-selected METADATA NAME DESTINATION` selects exactly one provider package
from a bounded Cargo metadata file, then consumes that package's lock. Unknown
repository owners, missing/duplicate assets, escaping paths and invalid exports
fail before execution.

The prepared native curl provider performs HTTPS through the official GitHub
release API. Its user configuration is disabled. Only HTTPS redirects are
accepted; authorization is not forwarded to another origin. An optional job
token reaches the API through a private header file and is never put in argv,
logs or exported variables. The owned header file is removed before publication.
The declared native curl provider and the consumer must be qualified together.

Size, time, input and archive budgets are finite. Downloads are streamed to the
owned destination, then hashed in bounded chunks. The exact locked bytes and
optional attestation are checked before extraction. Only declared regular
executables are materialized; links, special entries, duplicates and traversal
fail. Existing destinations are preserved, and failed preparation removes only
its newly owned destination. GITHUB_ENV receives validated executable paths
after the whole preparation succeeds.

The optional attestation mode retains the existing GitHub CLI verification
contract, including signer workflow, source ref and a bounded local bundle.
An attested provider also requires qualification of that native CLI and its
actual release evidence. A digest alone is not an attestation.

The current integration uses the same independently released Systeminfo archive
and lock; this tool changes no provider version, device, route or runtime cache.
Historical immutable Python-helper selections keep their original bytes until
their consuming repositories qualify a transition.

Original tooling: Apache-2.0. See LICENSE and NOTICE. No runtime module is
relicensed by this package.
