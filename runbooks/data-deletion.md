# Data deletion and retention

1. Resolve the data class and versioned policy; unknown classes are not deleted.
2. Produce a tenant-scoped dry run and canonical SHA-256 digest of exact record
   identifiers and backup locations.
3. Check minimum retention, legal holds, litigation requests, and regional
   obligations.
4. A different approver signs the dry-run digest. Any scope or digest change
   invalidates approval.
5. Execute with a current scheduler fencing token and write an immutable receipt
   containing affected counts and digest.
6. Verify backup expiry independently. Until that receipt exists, report
   deletion as pending rather than complete.
