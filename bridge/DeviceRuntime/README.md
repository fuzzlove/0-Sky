# Device bridge runtime source

This directory publishes the device broker and its `zero_sky_core` source for
audit. Deployment is performed only by the integrity-checked complete SRD Kit.
No bridge token, pairing registry, credentials, device identifiers, tickets,
logs, or personalized artifacts are included here.

The matching binary release is Runtime Manager **2.4.10**. This version bump is
intentional: package convergence must upgrade a 2.4.9 single-host broker before
the host writes a schema-2 trusted-Mac registry.
