package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

final class SqlScriptsTest {
    @Test
    void preservesSemicolonsInsideDollarQuotedFunctionsAndStrings() {
        String script = """
                CREATE TABLE sample(value text);
                CREATE FUNCTION f() RETURNS trigger AS $body$
                BEGIN NEW.value := 'a;b'; RETURN NEW; END;
                $body$ LANGUAGE plpgsql;
                """;
        assertEquals(2, SqlScripts.split(script).size());
    }

    @Test
    void rejectsUnterminatedLiterals() {
        assertThrows(IllegalArgumentException.class, () -> SqlScripts.split("SELECT 'broken;"));
    }

    @Test
    void preservesStatementsThatStartWithLineOrBlockComments() {
        String script = """
                -- migration provenance; this semicolon is not a delimiter
                CREATE TABLE first_table(id bigint);
                /* deployment note; still part of the next statement */
                CREATE TABLE second_table(id bigint);
                """;

        var statements = SqlScripts.split(script);

        assertEquals(2, statements.size());
        assertEquals(true, statements.get(0).startsWith("-- migration provenance"));
        assertEquals(true, statements.get(0).contains("CREATE TABLE first_table"));
        assertEquals(true, statements.get(1).startsWith("/* deployment note"));
        assertEquals(true, statements.get(1).contains("CREATE TABLE second_table"));
    }

    @Test
    void ignoresCommentOnlyFragmentsAndSupportsNestedBlockComments() {
        String script = """
                /* outer comment;
                   /* nested comment; */
                   still outer; */
                ;
                -- trailing comment only;
                """;

        assertEquals(0, SqlScripts.split(script).size());
        assertThrows(IllegalArgumentException.class,
                () -> SqlScripts.split("/* outer /* nested */ still open"));
    }
}
