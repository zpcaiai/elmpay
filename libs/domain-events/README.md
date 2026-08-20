# Domain Events boundary

This tracked boundary owns shared event-envelope contracts only. It must not own business orders or transport infrastructure; implementations require versioned schemas, tenant and correlation identifiers, compatibility rules, and inbox/outbox semantics.
