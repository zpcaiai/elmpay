package com.elmpay.gateway;

import java.util.ArrayList;
import java.util.List;

/** PostgreSQL statement splitter supporting comments, quoted strings and dollar-quoted functions. */
public final class SqlScripts {
    private SqlScripts() {
    }

    public static List<String> split(String script) {
        List<String> statements = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean singleQuote = false;
        boolean doubleQuote = false;
        boolean lineComment = false;
        int blockCommentDepth = 0;
        String dollarTag = null;
        for (int index = 0; index < script.length(); index++) {
            char character = script.charAt(index);
            char next = index + 1 < script.length() ? script.charAt(index + 1) : '\0';
            if (lineComment) {
                current.append(character);
                if (character == '\n') {
                    lineComment = false;
                }
                continue;
            }
            if (blockCommentDepth > 0) {
                current.append(character);
                if (character == '/' && next == '*') {
                    current.append(next);
                    index++;
                    blockCommentDepth++;
                } else if (character == '*' && next == '/') {
                    current.append(next);
                    index++;
                    blockCommentDepth--;
                }
                continue;
            }
            if (dollarTag != null) {
                if (script.startsWith(dollarTag, index)) {
                    current.append(dollarTag);
                    index += dollarTag.length() - 1;
                    dollarTag = null;
                } else {
                    current.append(character);
                }
                continue;
            }
            if (!singleQuote && !doubleQuote && character == '-' && next == '-') {
                current.append(character).append(next);
                index++;
                lineComment = true;
                continue;
            }
            if (!singleQuote && !doubleQuote && character == '/' && next == '*') {
                current.append(character).append(next);
                index++;
                blockCommentDepth = 1;
                continue;
            }
            if (!singleQuote && !doubleQuote && character == '$') {
                int end = script.indexOf('$', index + 1);
                if (end > index && script.substring(index + 1, end).matches("[A-Za-z0-9_]*")) {
                    dollarTag = script.substring(index, end + 1);
                    current.append(dollarTag);
                    index = end;
                    continue;
                }
            }
            if (!doubleQuote && character == '\'') {
                current.append(character);
                if (singleQuote && next == '\'') {
                    current.append(next);
                    index++;
                } else {
                    singleQuote = !singleQuote;
                }
                continue;
            }
            if (!singleQuote && character == '"') {
                current.append(character);
                if (doubleQuote && next == '"') {
                    current.append(next);
                    index++;
                } else {
                    doubleQuote = !doubleQuote;
                }
                continue;
            }
            if (character == ';' && !singleQuote && !doubleQuote) {
                add(statements, current);
                current.setLength(0);
            } else {
                current.append(character);
            }
        }
        add(statements, current);
        if (singleQuote || doubleQuote || blockCommentDepth > 0 || dollarTag != null) {
            throw new IllegalArgumentException("unterminated SQL literal or comment");
        }
        return List.copyOf(statements);
    }

    private static void add(List<String> statements, StringBuilder candidate) {
        String statement = candidate.toString().trim();
        if (!statement.isEmpty() && containsSqlOutsideComments(statement)) {
            statements.add(statement);
        }
    }

    /** Returns true when the candidate is more than whitespace and SQL comments. */
    private static boolean containsSqlOutsideComments(String candidate) {
        boolean lineComment = false;
        int blockCommentDepth = 0;
        for (int index = 0; index < candidate.length(); index++) {
            char character = candidate.charAt(index);
            char next = index + 1 < candidate.length() ? candidate.charAt(index + 1) : '\0';
            if (lineComment) {
                if (character == '\n' || character == '\r') {
                    lineComment = false;
                }
                continue;
            }
            if (blockCommentDepth > 0) {
                if (character == '/' && next == '*') {
                    blockCommentDepth++;
                    index++;
                } else if (character == '*' && next == '/') {
                    blockCommentDepth--;
                    index++;
                }
                continue;
            }
            if (character == '-' && next == '-') {
                lineComment = true;
                index++;
            } else if (character == '/' && next == '*') {
                blockCommentDepth = 1;
                index++;
            } else if (!Character.isWhitespace(character)) {
                return true;
            }
        }
        return false;
    }
}
