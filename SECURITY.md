# Security policy

EthBFT v0.3 is a pre-production alpha and has not received an independent
security audit. Do not use it to secure assets or a production network yet.

Report vulnerabilities privately through GitHub Security Advisories for this
repository. Do not open a public issue containing exploit details.

Only the latest published release line is eligible for security fixes. Engine
API endpoints must remain private and JWT-authenticated; leaked JWT secrets,
shared execution datadirs, or multiple forkchoice authorities are unsupported
and unsafe deployments.
