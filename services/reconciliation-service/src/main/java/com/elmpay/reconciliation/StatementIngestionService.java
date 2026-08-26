package com.elmpay.reconciliation;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.PushbackReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import javax.sql.DataSource;

/** Size-bounded, digest-deduplicated and parser-versioned statement intake. */
public final class StatementIngestionService {
    public enum Kind { PROVIDER, BANK }
    public record Row(String externalReference, long amountMinor, String currency, String eventType, Instant occurredAt) {}
    public record Ingested(String id, String tenantId, Kind kind, String source, String digest,
                           String parserVersion, List<Row> rows, boolean duplicate) {}

    private static final List<String> REQUIRED = List.of("external_reference", "amount_minor", "currency", "event_type", "occurred_at");
    private final DataSource dataSource;
    private final Clock clock;
    private final int maximumBytes;
    private final int maximumRows;

    public StatementIngestionService(DataSource dataSource, Clock clock, int maximumBytes, int maximumRows) {
        this.dataSource = Objects.requireNonNull(dataSource); this.clock = Objects.requireNonNull(clock);
        if (maximumBytes <= 0 || maximumRows <= 0) throw new IllegalArgumentException("intake limits must be positive");
        this.maximumBytes = maximumBytes; this.maximumRows = maximumRows;
    }

    public Ingested ingest(String tenantId, Kind kind, String source, String parserVersion, byte[] raw) throws SQLException {
        UUID tenant = TenantSession.tenant(tenantId);
        required(source); required(parserVersion); Objects.requireNonNull(kind); Objects.requireNonNull(raw);
        if (raw.length == 0 || raw.length > maximumBytes) throw new IllegalArgumentException("statement size outside configured bounds");
        String digest = sha256(raw);
        List<Row> rows = parse(raw);
        if (rows.size() > maximumRows) throw new IllegalArgumentException("statement row limit exceeded");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                TenantSession.setLocal(connection, tenant);
                UUID id = UUID.randomUUID();
                Savepoint insertion = connection.setSavepoint("statement_file_insert");
                try (PreparedStatement file = connection.prepareStatement(
                        "INSERT INTO statement_file(id,tenant_id,kind,source,sha256,parser_version,raw_bytes,ingested_at) VALUES (?,?,?,?,?,?,?,?)")) {
                    file.setObject(1, id); file.setObject(2, tenant); file.setString(3, kind.name()); file.setString(4, source);
                    file.setString(5, digest); file.setString(6, parserVersion); file.setBytes(7, raw); file.setTimestamp(8, java.sql.Timestamp.from(clock.instant()));
                    file.executeUpdate();
                    connection.releaseSavepoint(insertion);
                } catch (SQLException duplicate) {
                    // Clear PostgreSQL's failed-transaction state before querying
                    // the durable record that won the unique-key race.
                    TenantSession.rollbackUniqueConflict(connection, insertion, duplicate);
                    String existing = existingId(connection, tenant, kind, source, digest, parserVersion);
                    connection.commit();
                    return new Ingested(existing, tenant.toString(), kind, source, digest,
                            parserVersion, List.copyOf(rows), true);
                }
                try (PreparedStatement row = connection.prepareStatement(
                        "INSERT INTO statement_row(id,tenant_id,file_id,row_number,external_reference,amount_minor,currency,event_type,occurred_at) VALUES (?,?,?,?,?,?,?,?,?)")) {
                    for (int index = 0; index < rows.size(); index++) {
                        Row value = rows.get(index);
                        row.setObject(1, UUID.randomUUID()); row.setObject(2, tenant); row.setObject(3, id);
                        row.setInt(4, index + 2); row.setString(5, value.externalReference()); row.setLong(6, value.amountMinor());
                        row.setString(7, value.currency()); row.setString(8, value.eventType()); row.setTimestamp(9, java.sql.Timestamp.from(value.occurredAt())); row.addBatch();
                    }
                    row.executeBatch();
                }
                connection.commit();
                return new Ingested(id.toString(), tenant.toString(), kind, source, digest,
                        parserVersion, List.copyOf(rows), false);
            } catch (RuntimeException | SQLException failure) {
                TenantSession.rollback(connection, failure);
                throw failure;
            }
        }
    }

    public List<Row> parse(byte[] raw) {
        if (raw.length >= 3 && (raw[0] & 0xff) == 0xef && (raw[1] & 0xff) == 0xbb && (raw[2] & 0xff) == 0xbf)
            throw new IllegalArgumentException("UTF-8 BOM is not accepted; source encoding must be explicit");
        String text = new String(raw, StandardCharsets.UTF_8);
        if (text.indexOf('\u0000') >= 0) throw new IllegalArgumentException("NUL byte in statement");
        List<List<String>> records = csv(text);
        if (records.size() < 2) throw new IllegalArgumentException("statement has no data rows");
        Map<String, Integer> columns = new HashMap<>();
        for (int i = 0; i < records.get(0).size(); i++) columns.put(records.get(0).get(i).trim().toLowerCase(Locale.ROOT), i);
        if (!columns.keySet().containsAll(REQUIRED)) throw new IllegalArgumentException("required statement columns missing");
        List<Row> rows = new ArrayList<>();
        for (int line = 1; line < records.size(); line++) {
            List<String> fields = records.get(line);
            if (fields.size() != records.get(0).size()) throw new IllegalArgumentException("inconsistent column count at row " + (line + 1));
            try {
                String reference = value(fields, columns, "external_reference"); required(reference);
                long amount = Long.parseLong(value(fields, columns, "amount_minor"));
                String currency = value(fields, columns, "currency").toUpperCase(Locale.ROOT);
                if (!currency.matches("[A-Z]{3}")) throw new IllegalArgumentException("invalid currency");
                String event = value(fields, columns, "event_type"); required(event);
                rows.add(new Row(reference, amount, currency, event, Instant.parse(value(fields, columns, "occurred_at"))));
            } catch (NumberFormatException | DateTimeParseException invalid) {
                throw new IllegalArgumentException("invalid statement value at row " + (line + 1), invalid);
            }
        }
        return List.copyOf(rows);
    }

    private static List<List<String>> csv(String input) {
        List<List<String>> records = new ArrayList<>(); List<String> row = new ArrayList<>(); StringBuilder field = new StringBuilder();
        boolean quoted = false;
        try (PushbackReader reader = new PushbackReader(new InputStreamReader(
                new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8))) {
            int current;
            while ((current = reader.read()) != -1) {
                char ch = (char) current;
                if (quoted) {
                    if (ch == '"') {
                        int next = reader.read();
                        if (next == '"') field.append('"');
                        else { quoted = false; if (next != -1) reader.unread(next); }
                    } else field.append(ch);
                } else if (ch == '"' && field.length() == 0) quoted = true;
                else if (ch == ',') { row.add(field.toString()); field.setLength(0); }
                else if (ch == '\n') { row.add(stripCr(field)); field.setLength(0); if (!blank(row)) records.add(List.copyOf(row)); row.clear(); }
                else field.append(ch);
            }
        } catch (java.io.IOException impossible) { throw new IllegalStateException(impossible); }
        if (quoted) throw new IllegalArgumentException("unterminated quoted field");
        if (field.length() > 0 || !row.isEmpty()) { row.add(stripCr(field)); if (!blank(row)) records.add(List.copyOf(row)); }
        return records;
    }
    private static String stripCr(StringBuilder field) {
        int length = field.length(); if (length > 0 && field.charAt(length - 1) == '\r') field.setLength(length - 1); return field.toString();
    }
    private static boolean blank(List<String> row) { return row.stream().allMatch(String::isBlank); }
    private static String value(List<String> row, Map<String, Integer> columns, String name) { return row.get(columns.get(name)).trim(); }
    private static String existingId(Connection connection, UUID tenant, Kind kind, String source, String digest, String parserVersion) throws SQLException {
        try (PreparedStatement query = connection.prepareStatement("SELECT id FROM statement_file WHERE tenant_id=? AND kind=? AND source=? AND sha256=? AND parser_version=?")) {
            query.setObject(1, tenant); query.setString(2, kind.name()); query.setString(3, source); query.setString(4, digest); query.setString(5, parserVersion);
            try (ResultSet result = query.executeQuery()) { if (!result.next()) throw new IllegalStateException("digest conflict without existing file"); return result.getString(1); }
        }
    }
    private static String sha256(byte[] value) {
        try { return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (NoSuchAlgorithmException unavailable) { throw new IllegalStateException(unavailable); }
    }
    private static void required(String value) { if (value == null || value.isBlank()) throw new IllegalArgumentException("required value missing"); }
}
