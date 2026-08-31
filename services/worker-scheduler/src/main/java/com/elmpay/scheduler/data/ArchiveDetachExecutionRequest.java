package com.elmpay.scheduler.data;

import com.elmpay.events.StrictJson;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Non-secret pointer to one independently verified, still-pending detach authorization. */
record ArchiveDetachExecutionRequest(UUID releaseId, String partitionName,
        String canonicalAuthorizationDigest) {
    ArchiveDetachExecutionRequest {
        if (releaseId == null || partitionName == null
                || !partitionName.matches("tenant_archive_fact_[0-9]{6}")
                || canonicalAuthorizationDigest == null
                || !canonicalAuthorizationDigest.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("archive detach execution request is invalid");
        }
    }

    static ArchiveDetachExecutionRequest load(Path path) {
        Map<String, Object> document = StrictJson.object(
                ArchiveReceiptVerifier.readBounded(path, 16_384));
        if (!document.keySet().equals(Set.of(
                "schemaVersion", "releaseId", "partitionName",
                "canonicalAuthorizationDigest"))
                || !Long.valueOf(1).equals(document.get("schemaVersion"))) {
            throw new IllegalArgumentException("archive detach execution request is not exact");
        }
        String rawId = text(document, "releaseId", 36);
        UUID releaseId;
        try {
            releaseId = UUID.fromString(rawId);
            if (!releaseId.toString().equals(rawId)) {
                throw new IllegalArgumentException("releaseId is not canonical");
            }
        } catch (IllegalArgumentException failure) {
            throw new IllegalArgumentException("releaseId is not a canonical UUID", failure);
        }
        return new ArchiveDetachExecutionRequest(releaseId,
                text(document, "partitionName", 64),
                text(document, "canonicalAuthorizationDigest", 64));
    }

    private static String text(Map<String, Object> document, String field, int maximum) {
        Object raw = document.get(field);
        if (!(raw instanceof String text) || text.isEmpty() || text.length() > maximum
                || !text.equals(text.trim())
                || text.chars().anyMatch(character -> character < 0x20)) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return text;
    }
}
