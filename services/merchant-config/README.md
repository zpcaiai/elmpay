# Merchant Config service

The Java module provides tenant/project-bound provider accounts, external secret references,
capability filtering, deterministic routing and a PostgreSQL read model. Routing fails closed when
no active account satisfies the immutable payment constraints. Production activation still needs
provider callback and test-transaction evidence plus independent approval.
