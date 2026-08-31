package com.elmpay.reconciliation;

import java.io.PushbackReader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
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
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
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

    public Ingested ingest(String tenantId, Kind kind, String source, String parserVersion,
            byte[] raw) throws SQLException {
        UUID tenant = TenantSession.tenant(tenantId);
        Objects.requireNonNull(kind); Objects.requireNonNull(raw);
        String provider = reconciliationProvider(kind, source);
        if (parserVersion == null || !parserVersion.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")) {
            throw new IllegalArgumentException("parserVersion has an invalid format");
        }
        if (raw.length == 0 || raw.length > maximumBytes) {
            throw new IllegalArgumentException("statement size outside configured bounds");
        }
        byte[] immutableRaw = raw.clone();
        try {
            String digest = sha256(immutableRaw);
            List<Row> rows = parse(immutableRaw);
            if (rows.size() > maximumRows) {
                throw new IllegalArgumentException("statement row limit exceeded");
            }
            Instant latestAllowed = clock.instant().plusSeconds(300);
            if (rows.stream().anyMatch(row -> row.occurredAt().isAfter(latestAllowed))) {
                throw new IllegalArgumentException(
                        "statement contains a future-dated financial fact");
            }
            try (Connection connection = dataSource.getConnection()) {
                connection.setAutoCommit(false);
                try {
                    TenantSession.setLocal(connection, tenant);
                    UUID id = UUID.randomUUID();
                    Savepoint insertion = connection.setSavepoint("statement_file_insert");
                    try (PreparedStatement file = connection.prepareStatement("""
                            INSERT INTO statement_file
                              (id,tenant_id,kind,source,sha256,parser_version,raw_bytes,ingested_at,
                               reconciliation_provider)
                            VALUES (?,?,?,?,?,?,?,?,?)
                            """)) {
                        file.setObject(1, id);
                        file.setObject(2, tenant);
                        file.setString(3, kind.name());
                        file.setString(4, source);
                        file.setString(5, digest);
                        file.setString(6, parserVersion);
                        file.setBytes(7, immutableRaw);
                        file.setTimestamp(8, java.sql.Timestamp.from(clock.instant()));
                        file.setString(9, provider);
                        file.executeUpdate();
                        connection.releaseSavepoint(insertion);
                    } catch (SQLException duplicate) {
                        // Clear PostgreSQL's failed-transaction state before querying
                        // the durable record that won the unique-key race.
                        TenantSession.rollbackUniqueConflict(connection, insertion, duplicate);
                        String existing = existingId(connection, tenant, kind, source, digest,
                                parserVersion);
                        connection.commit();
                        return new Ingested(existing, tenant.toString(), kind, source, digest,
                                parserVersion, List.copyOf(rows), true);
                    }
                    try (PreparedStatement row = connection.prepareStatement(
                            "INSERT INTO statement_row(id,tenant_id,file_id,row_number,external_reference,amount_minor,currency,event_type,occurred_at) VALUES (?,?,?,?,?,?,?,?,?)")) {
                        for (int index = 0; index < rows.size(); index++) {
                            Row value = rows.get(index);
                            row.setObject(1, UUID.randomUUID());
                            row.setObject(2, tenant);
                            row.setObject(3, id);
                            row.setInt(4, index + 2);
                            row.setString(5, value.externalReference());
                            row.setLong(6, value.amountMinor());
                            row.setString(7, value.currency());
                            row.setString(8, value.eventType());
                            row.setTimestamp(9,
                                    java.sql.Timestamp.from(value.occurredAt()));
                            row.addBatch();
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
        } finally {
            java.util.Arrays.fill(immutableRaw, (byte) 0);
        }
    }

    public List<Row> parse(byte[] raw) {
        Objects.requireNonNull(raw, "raw");
        if (raw.length == 0 || raw.length > maximumBytes) {
            throw new IllegalArgumentException("statement size outside configured bounds");
        }
        if (raw.length >= 3 && (raw[0] & 0xff) == 0xef && (raw[1] & 0xff) == 0xbb && (raw[2] & 0xff) == 0xbf)
            throw new IllegalArgumentException("UTF-8 BOM is not accepted; source encoding must be explicit");
        final String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(raw)).toString();
        } catch (CharacterCodingException failure) {
            throw new IllegalArgumentException("statement is not strict UTF-8", failure);
        }
        if (text.indexOf('\u0000') >= 0) throw new IllegalArgumentException("NUL byte in statement");
        List<List<String>> records = csv(text);
        if (records.size() < 2) throw new IllegalArgumentException("statement has no data rows");
        Map<String, Integer> columns = new HashMap<>();
        for (int i = 0; i < records.get(0).size(); i++) {
            String name = records.get(0).get(i).trim().toLowerCase(Locale.ROOT);
            if (name.isEmpty() || columns.putIfAbsent(name, i) != null) {
                throw new IllegalArgumentException("statement header is blank or duplicated");
            }
        }
        if (!columns.keySet().equals(new HashSet<>(REQUIRED))) {
            throw new IllegalArgumentException("statement header must equal the governed schema");
        }
        List<Row> rows = new ArrayList<>();
        for (int line = 1; line < records.size(); line++) {
            if (rows.size() >= maximumRows) {
                throw new IllegalArgumentException("statement row limit exceeded");
            }
            List<String> fields = records.get(line);
            if (fields.size() != records.get(0).size()) throw new IllegalArgumentException("inconsistent column count at row " + (line + 1));
            try {
                String reference = value(fields, columns, "external_reference");
                if (reference.isBlank() || reference.length() > 160
                        || reference.chars().anyMatch(character -> character < 0x20)) {
                    throw new IllegalArgumentException("invalid external reference");
                }
                long amount = Long.parseLong(value(fields, columns, "amount_minor"));
                if (amount <= 0) throw new IllegalArgumentException("amount must be positive");
                String currency = value(fields, columns, "currency").toUpperCase(Locale.ROOT);
                if (!currency.matches("[A-Z]{3}")) throw new IllegalArgumentException("invalid currency");
                String event = value(fields, columns, "event_type").toUpperCase(Locale.ROOT);
                if (!java.util.Set.of("CAPTURE", "REFUND").contains(event)) {
                    throw new IllegalArgumentException("unsupported statement event type");
                }
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
        boolean closedQuote = false;
        try (PushbackReader reader = new PushbackReader(new StringReader(input))) {
            int current;
            while ((current = reader.read()) != -1) {
                char ch = (char) current;
                if (quoted) {
                    if (ch == '"') {
                        int next = reader.read();
                        if (next == '"') field.append('"');
                        else {
                            quoted = false;
                            closedQuote = true;
                            if (next != -1) reader.unread(next);
                        }
                    } else field.append(ch);
                } else if (closedQuote) {
                    if (ch == ',') {
                        row.add(field.toString()); field.setLength(0); closedQuote = false;
                    } else if (ch == '\n') {
                        row.add(field.toString()); field.setLength(0);
                        if (!blank(row)) records.add(List.copyOf(row));
                        row.clear(); closedQuote = false;
                    } else if (ch == '\r') {
                        int next = reader.read();
                        if (next != '\n') {
                            throw new IllegalArgumentException(
                                    "character after closing quote");
                        }
                        row.add(field.toString()); field.setLength(0);
                        if (!blank(row)) records.add(List.copyOf(row));
                        row.clear(); closedQuote = false;
                    } else {
                        throw new IllegalArgumentException("character after closing quote");
                    }
                } else if (ch == '"' && field.length() == 0) quoted = true;
                else if (ch == '"') throw new IllegalArgumentException("quote in unquoted field");
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
        try (PreparedStatement query = connection.prepareStatement("SELECT id FROM statement_file WHERE tenant_id=? AND kind=? AND source=? AND content_sha256=? AND parser_version=?")) {
            query.setObject(1, tenant); query.setString(2, kind.name()); query.setString(3, source); query.setString(4, digest); query.setString(5, parserVersion);
            try (ResultSet result = query.executeQuery()) { if (!result.next()) throw new IllegalStateException("digest conflict without existing file"); return result.getString(1); }
        }
    }
    private static String sha256(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (NoSuchAlgorithmException unavailable) { throw new IllegalStateException(unavailable); }
    }
    private static String reconciliationProvider(Kind kind, String source) {
        if (source == null || source.isBlank() || source.length() > 160
                || !source.equals(source.trim())
                || !source.equals(source.toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("statement source has an invalid format");
        }
        String[] parts = source.toLowerCase(Locale.ROOT).split(":", -1);
        if (!java.util.Set.of("wechat", "alipay", "stripe", "paypal", "apple_pay")
                .contains(parts[0])) {
            throw new IllegalArgumentException("statement source has no governed provider");
        }
        if ((kind == Kind.PROVIDER && parts.length != 1)
                || (kind == Kind.BANK && (parts.length != 2
                        || !parts[1].matches("[a-z0-9][a-z0-9._-]{0,119}")))) {
            throw new IllegalArgumentException(
                    "provider source is provider; bank source is provider:account");
        }
        return parts[0];
    }
}
