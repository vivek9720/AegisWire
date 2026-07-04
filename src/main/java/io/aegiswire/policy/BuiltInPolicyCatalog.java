package io.aegiswire.policy;
import io.aegiswire.core.*; import java.util.*;
public final class BuiltInPolicyCatalog {
    private BuiltInPolicyCatalog() {}
    public static PolicyBundle defaultBundle() {
        List<Rule> rules = new ArrayList<Rule>();
        rules.add(new Rule("builtin-http-000", Severity.HIGH, 5,
            "Built-in http telemetry signal 0",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin", false))));
        rules.add(new Rule("builtin-http-001", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 1",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner", false))));
        rules.add(new Rule("builtin-dns-002", Severity.LOW, 15,
            "Built-in dns telemetry signal 2",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip", false))));
        rules.add(new Rule("builtin-tls-003", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 3",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login", false))));
        rules.add(new Rule("builtin-log-004", Severity.LOW, 25,
            "Built-in log telemetry signal 4",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny", false))));
        rules.add(new Rule("builtin-http-005", Severity.HIGH, 30,
            "Built-in http telemetry signal 5",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin5", false))));
        rules.add(new Rule("builtin-http-006", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 6",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner6", false))));
        rules.add(new Rule("builtin-dns-007", Severity.LOW, 40,
            "Built-in dns telemetry signal 7",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip7", false))));
        rules.add(new Rule("builtin-tls-008", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 8",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login8", false))));
        rules.add(new Rule("builtin-log-009", Severity.LOW, 5,
            "Built-in log telemetry signal 9",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny9", false))));
        rules.add(new Rule("builtin-http-010", Severity.HIGH, 10,
            "Built-in http telemetry signal 10",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin10", false))));
        rules.add(new Rule("builtin-http-011", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 11",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner11", false))));
        rules.add(new Rule("builtin-dns-012", Severity.LOW, 20,
            "Built-in dns telemetry signal 12",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip12", false))));
        rules.add(new Rule("builtin-tls-013", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 13",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login13", false))));
        rules.add(new Rule("builtin-log-014", Severity.LOW, 30,
            "Built-in log telemetry signal 14",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny14", false))));
        rules.add(new Rule("builtin-http-015", Severity.HIGH, 35,
            "Built-in http telemetry signal 15",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin15", false))));
        rules.add(new Rule("builtin-http-016", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 16",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner16", false))));
        rules.add(new Rule("builtin-dns-017", Severity.LOW, 45,
            "Built-in dns telemetry signal 17",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip17", false))));
        rules.add(new Rule("builtin-tls-018", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 18",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login18", false))));
        rules.add(new Rule("builtin-log-019", Severity.LOW, 10,
            "Built-in log telemetry signal 19",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny19", false))));
        rules.add(new Rule("builtin-http-020", Severity.HIGH, 15,
            "Built-in http telemetry signal 20",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin20", false))));
        rules.add(new Rule("builtin-http-021", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 21",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner21", false))));
        rules.add(new Rule("builtin-dns-022", Severity.LOW, 25,
            "Built-in dns telemetry signal 22",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip22", false))));
        rules.add(new Rule("builtin-tls-023", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 23",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login23", false))));
        rules.add(new Rule("builtin-log-024", Severity.LOW, 35,
            "Built-in log telemetry signal 24",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny24", false))));
        rules.add(new Rule("builtin-http-025", Severity.HIGH, 40,
            "Built-in http telemetry signal 25",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin25", false))));
        rules.add(new Rule("builtin-http-026", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 26",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner26", false))));
        rules.add(new Rule("builtin-dns-027", Severity.LOW, 5,
            "Built-in dns telemetry signal 27",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip27", false))));
        rules.add(new Rule("builtin-tls-028", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 28",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login28", false))));
        rules.add(new Rule("builtin-log-029", Severity.LOW, 15,
            "Built-in log telemetry signal 29",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny29", false))));
        rules.add(new Rule("builtin-http-030", Severity.HIGH, 20,
            "Built-in http telemetry signal 30",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin30", false))));
        rules.add(new Rule("builtin-http-031", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 31",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner31", false))));
        rules.add(new Rule("builtin-dns-032", Severity.LOW, 30,
            "Built-in dns telemetry signal 32",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip32", false))));
        rules.add(new Rule("builtin-tls-033", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 33",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login33", false))));
        rules.add(new Rule("builtin-log-034", Severity.LOW, 40,
            "Built-in log telemetry signal 34",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny34", false))));
        rules.add(new Rule("builtin-http-035", Severity.HIGH, 45,
            "Built-in http telemetry signal 35",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin35", false))));
        rules.add(new Rule("builtin-http-036", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 36",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner36", false))));
        rules.add(new Rule("builtin-dns-037", Severity.LOW, 10,
            "Built-in dns telemetry signal 37",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip37", false))));
        rules.add(new Rule("builtin-tls-038", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 38",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login38", false))));
        rules.add(new Rule("builtin-log-039", Severity.LOW, 20,
            "Built-in log telemetry signal 39",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny39", false))));
        rules.add(new Rule("builtin-http-040", Severity.HIGH, 25,
            "Built-in http telemetry signal 40",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin40", false))));
        rules.add(new Rule("builtin-http-041", Severity.MEDIUM, 30,
            "Built-in http telemetry signal 41",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner41", false))));
        rules.add(new Rule("builtin-dns-042", Severity.LOW, 35,
            "Built-in dns telemetry signal 42",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip42", false))));
        rules.add(new Rule("builtin-tls-043", Severity.MEDIUM, 40,
            "Built-in tls telemetry signal 43",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login43", false))));
        rules.add(new Rule("builtin-log-044", Severity.LOW, 45,
            "Built-in log telemetry signal 44",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny44", false))));
        rules.add(new Rule("builtin-http-045", Severity.HIGH, 5,
            "Built-in http telemetry signal 45",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin45", false))));
        rules.add(new Rule("builtin-http-046", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 46",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner46", false))));
        rules.add(new Rule("builtin-dns-047", Severity.LOW, 15,
            "Built-in dns telemetry signal 47",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip47", false))));
        rules.add(new Rule("builtin-tls-048", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 48",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login48", false))));
        rules.add(new Rule("builtin-log-049", Severity.LOW, 25,
            "Built-in log telemetry signal 49",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny49", false))));
        rules.add(new Rule("builtin-http-050", Severity.HIGH, 30,
            "Built-in http telemetry signal 50",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin50", false))));
        rules.add(new Rule("builtin-http-051", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 51",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner51", false))));
        rules.add(new Rule("builtin-dns-052", Severity.LOW, 40,
            "Built-in dns telemetry signal 52",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip52", false))));
        rules.add(new Rule("builtin-tls-053", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 53",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login53", false))));
        rules.add(new Rule("builtin-log-054", Severity.LOW, 5,
            "Built-in log telemetry signal 54",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny54", false))));
        rules.add(new Rule("builtin-http-055", Severity.HIGH, 10,
            "Built-in http telemetry signal 55",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin55", false))));
        rules.add(new Rule("builtin-http-056", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 56",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner56", false))));
        rules.add(new Rule("builtin-dns-057", Severity.LOW, 20,
            "Built-in dns telemetry signal 57",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip57", false))));
        rules.add(new Rule("builtin-tls-058", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 58",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login58", false))));
        rules.add(new Rule("builtin-log-059", Severity.LOW, 30,
            "Built-in log telemetry signal 59",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny59", false))));
        rules.add(new Rule("builtin-http-060", Severity.HIGH, 35,
            "Built-in http telemetry signal 60",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin60", false))));
        rules.add(new Rule("builtin-http-061", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 61",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner61", false))));
        rules.add(new Rule("builtin-dns-062", Severity.LOW, 45,
            "Built-in dns telemetry signal 62",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip62", false))));
        rules.add(new Rule("builtin-tls-063", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 63",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login63", false))));
        rules.add(new Rule("builtin-log-064", Severity.LOW, 10,
            "Built-in log telemetry signal 64",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny64", false))));
        rules.add(new Rule("builtin-http-065", Severity.HIGH, 15,
            "Built-in http telemetry signal 65",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin65", false))));
        rules.add(new Rule("builtin-http-066", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 66",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner66", false))));
        rules.add(new Rule("builtin-dns-067", Severity.LOW, 25,
            "Built-in dns telemetry signal 67",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip67", false))));
        rules.add(new Rule("builtin-tls-068", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 68",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login68", false))));
        rules.add(new Rule("builtin-log-069", Severity.LOW, 35,
            "Built-in log telemetry signal 69",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny69", false))));
        rules.add(new Rule("builtin-http-070", Severity.HIGH, 40,
            "Built-in http telemetry signal 70",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin70", false))));
        rules.add(new Rule("builtin-http-071", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 71",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner71", false))));
        rules.add(new Rule("builtin-dns-072", Severity.LOW, 5,
            "Built-in dns telemetry signal 72",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip72", false))));
        rules.add(new Rule("builtin-tls-073", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 73",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login73", false))));
        rules.add(new Rule("builtin-log-074", Severity.LOW, 15,
            "Built-in log telemetry signal 74",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny74", false))));
        rules.add(new Rule("builtin-http-075", Severity.HIGH, 20,
            "Built-in http telemetry signal 75",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin75", false))));
        rules.add(new Rule("builtin-http-076", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 76",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner76", false))));
        rules.add(new Rule("builtin-dns-077", Severity.LOW, 30,
            "Built-in dns telemetry signal 77",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip77", false))));
        rules.add(new Rule("builtin-tls-078", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 78",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login78", false))));
        rules.add(new Rule("builtin-log-079", Severity.LOW, 40,
            "Built-in log telemetry signal 79",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny79", false))));
        rules.add(new Rule("builtin-http-080", Severity.HIGH, 45,
            "Built-in http telemetry signal 80",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin80", false))));
        rules.add(new Rule("builtin-http-081", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 81",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner81", false))));
        rules.add(new Rule("builtin-dns-082", Severity.LOW, 10,
            "Built-in dns telemetry signal 82",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip82", false))));
        rules.add(new Rule("builtin-tls-083", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 83",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login83", false))));
        rules.add(new Rule("builtin-log-084", Severity.LOW, 20,
            "Built-in log telemetry signal 84",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny84", false))));
        rules.add(new Rule("builtin-http-085", Severity.HIGH, 25,
            "Built-in http telemetry signal 85",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin85", false))));
        rules.add(new Rule("builtin-http-086", Severity.MEDIUM, 30,
            "Built-in http telemetry signal 86",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner86", false))));
        rules.add(new Rule("builtin-dns-087", Severity.LOW, 35,
            "Built-in dns telemetry signal 87",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip87", false))));
        rules.add(new Rule("builtin-tls-088", Severity.MEDIUM, 40,
            "Built-in tls telemetry signal 88",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login88", false))));
        rules.add(new Rule("builtin-log-089", Severity.LOW, 45,
            "Built-in log telemetry signal 89",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny89", false))));
        rules.add(new Rule("builtin-http-090", Severity.HIGH, 5,
            "Built-in http telemetry signal 90",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin90", false))));
        rules.add(new Rule("builtin-http-091", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 91",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner91", false))));
        rules.add(new Rule("builtin-dns-092", Severity.LOW, 15,
            "Built-in dns telemetry signal 92",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip92", false))));
        rules.add(new Rule("builtin-tls-093", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 93",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login93", false))));
        rules.add(new Rule("builtin-log-094", Severity.LOW, 25,
            "Built-in log telemetry signal 94",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny94", false))));
        rules.add(new Rule("builtin-http-095", Severity.HIGH, 30,
            "Built-in http telemetry signal 95",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin95", false))));
        rules.add(new Rule("builtin-http-096", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 96",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner96", false))));
        rules.add(new Rule("builtin-dns-097", Severity.LOW, 40,
            "Built-in dns telemetry signal 97",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip97", false))));
        rules.add(new Rule("builtin-tls-098", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 98",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login98", false))));
        rules.add(new Rule("builtin-log-099", Severity.LOW, 5,
            "Built-in log telemetry signal 99",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny99", false))));
        rules.add(new Rule("builtin-http-100", Severity.HIGH, 10,
            "Built-in http telemetry signal 100",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin100", false))));
        rules.add(new Rule("builtin-http-101", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 101",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner101", false))));
        rules.add(new Rule("builtin-dns-102", Severity.LOW, 20,
            "Built-in dns telemetry signal 102",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip102", false))));
        rules.add(new Rule("builtin-tls-103", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 103",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login103", false))));
        rules.add(new Rule("builtin-log-104", Severity.LOW, 30,
            "Built-in log telemetry signal 104",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny104", false))));
        rules.add(new Rule("builtin-http-105", Severity.HIGH, 35,
            "Built-in http telemetry signal 105",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin105", false))));
        rules.add(new Rule("builtin-http-106", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 106",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner106", false))));
        rules.add(new Rule("builtin-dns-107", Severity.LOW, 45,
            "Built-in dns telemetry signal 107",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip107", false))));
        rules.add(new Rule("builtin-tls-108", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 108",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login108", false))));
        rules.add(new Rule("builtin-log-109", Severity.LOW, 10,
            "Built-in log telemetry signal 109",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny109", false))));
        rules.add(new Rule("builtin-http-110", Severity.HIGH, 15,
            "Built-in http telemetry signal 110",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin110", false))));
        rules.add(new Rule("builtin-http-111", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 111",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner111", false))));
        rules.add(new Rule("builtin-dns-112", Severity.LOW, 25,
            "Built-in dns telemetry signal 112",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip112", false))));
        rules.add(new Rule("builtin-tls-113", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 113",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login113", false))));
        rules.add(new Rule("builtin-log-114", Severity.LOW, 35,
            "Built-in log telemetry signal 114",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny114", false))));
        rules.add(new Rule("builtin-http-115", Severity.HIGH, 40,
            "Built-in http telemetry signal 115",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin115", false))));
        rules.add(new Rule("builtin-http-116", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 116",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner116", false))));
        rules.add(new Rule("builtin-dns-117", Severity.LOW, 5,
            "Built-in dns telemetry signal 117",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip117", false))));
        rules.add(new Rule("builtin-tls-118", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 118",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login118", false))));
        rules.add(new Rule("builtin-log-119", Severity.LOW, 15,
            "Built-in log telemetry signal 119",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny119", false))));
        rules.add(new Rule("builtin-http-120", Severity.HIGH, 20,
            "Built-in http telemetry signal 120",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin120", false))));
        rules.add(new Rule("builtin-http-121", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 121",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner121", false))));
        rules.add(new Rule("builtin-dns-122", Severity.LOW, 30,
            "Built-in dns telemetry signal 122",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip122", false))));
        rules.add(new Rule("builtin-tls-123", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 123",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login123", false))));
        rules.add(new Rule("builtin-log-124", Severity.LOW, 40,
            "Built-in log telemetry signal 124",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny124", false))));
        rules.add(new Rule("builtin-http-125", Severity.HIGH, 45,
            "Built-in http telemetry signal 125",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin125", false))));
        rules.add(new Rule("builtin-http-126", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 126",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner126", false))));
        rules.add(new Rule("builtin-dns-127", Severity.LOW, 10,
            "Built-in dns telemetry signal 127",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip127", false))));
        rules.add(new Rule("builtin-tls-128", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 128",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login128", false))));
        rules.add(new Rule("builtin-log-129", Severity.LOW, 20,
            "Built-in log telemetry signal 129",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny129", false))));
        rules.add(new Rule("builtin-http-130", Severity.HIGH, 25,
            "Built-in http telemetry signal 130",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin130", false))));
        rules.add(new Rule("builtin-http-131", Severity.MEDIUM, 30,
            "Built-in http telemetry signal 131",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner131", false))));
        rules.add(new Rule("builtin-dns-132", Severity.LOW, 35,
            "Built-in dns telemetry signal 132",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip132", false))));
        rules.add(new Rule("builtin-tls-133", Severity.MEDIUM, 40,
            "Built-in tls telemetry signal 133",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login133", false))));
        rules.add(new Rule("builtin-log-134", Severity.LOW, 45,
            "Built-in log telemetry signal 134",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny134", false))));
        rules.add(new Rule("builtin-http-135", Severity.HIGH, 5,
            "Built-in http telemetry signal 135",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin135", false))));
        rules.add(new Rule("builtin-http-136", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 136",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner136", false))));
        rules.add(new Rule("builtin-dns-137", Severity.LOW, 15,
            "Built-in dns telemetry signal 137",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip137", false))));
        rules.add(new Rule("builtin-tls-138", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 138",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login138", false))));
        rules.add(new Rule("builtin-log-139", Severity.LOW, 25,
            "Built-in log telemetry signal 139",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny139", false))));
        rules.add(new Rule("builtin-http-140", Severity.HIGH, 30,
            "Built-in http telemetry signal 140",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin140", false))));
        rules.add(new Rule("builtin-http-141", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 141",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner141", false))));
        rules.add(new Rule("builtin-dns-142", Severity.LOW, 40,
            "Built-in dns telemetry signal 142",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip142", false))));
        rules.add(new Rule("builtin-tls-143", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 143",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login143", false))));
        rules.add(new Rule("builtin-log-144", Severity.LOW, 5,
            "Built-in log telemetry signal 144",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny144", false))));
        rules.add(new Rule("builtin-http-145", Severity.HIGH, 10,
            "Built-in http telemetry signal 145",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin145", false))));
        rules.add(new Rule("builtin-http-146", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 146",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner146", false))));
        rules.add(new Rule("builtin-dns-147", Severity.LOW, 20,
            "Built-in dns telemetry signal 147",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip147", false))));
        rules.add(new Rule("builtin-tls-148", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 148",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login148", false))));
        rules.add(new Rule("builtin-log-149", Severity.LOW, 30,
            "Built-in log telemetry signal 149",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny149", false))));
        rules.add(new Rule("builtin-http-150", Severity.HIGH, 35,
            "Built-in http telemetry signal 150",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin150", false))));
        rules.add(new Rule("builtin-http-151", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 151",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner151", false))));
        rules.add(new Rule("builtin-dns-152", Severity.LOW, 45,
            "Built-in dns telemetry signal 152",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip152", false))));
        rules.add(new Rule("builtin-tls-153", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 153",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login153", false))));
        rules.add(new Rule("builtin-log-154", Severity.LOW, 10,
            "Built-in log telemetry signal 154",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny154", false))));
        rules.add(new Rule("builtin-http-155", Severity.HIGH, 15,
            "Built-in http telemetry signal 155",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin155", false))));
        rules.add(new Rule("builtin-http-156", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 156",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner156", false))));
        rules.add(new Rule("builtin-dns-157", Severity.LOW, 25,
            "Built-in dns telemetry signal 157",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip157", false))));
        rules.add(new Rule("builtin-tls-158", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 158",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login158", false))));
        rules.add(new Rule("builtin-log-159", Severity.LOW, 35,
            "Built-in log telemetry signal 159",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny159", false))));
        rules.add(new Rule("builtin-http-160", Severity.HIGH, 40,
            "Built-in http telemetry signal 160",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin160", false))));
        rules.add(new Rule("builtin-http-161", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 161",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner161", false))));
        rules.add(new Rule("builtin-dns-162", Severity.LOW, 5,
            "Built-in dns telemetry signal 162",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip162", false))));
        rules.add(new Rule("builtin-tls-163", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 163",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login163", false))));
        rules.add(new Rule("builtin-log-164", Severity.LOW, 15,
            "Built-in log telemetry signal 164",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny164", false))));
        rules.add(new Rule("builtin-http-165", Severity.HIGH, 20,
            "Built-in http telemetry signal 165",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin165", false))));
        rules.add(new Rule("builtin-http-166", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 166",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner166", false))));
        rules.add(new Rule("builtin-dns-167", Severity.LOW, 30,
            "Built-in dns telemetry signal 167",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip167", false))));
        rules.add(new Rule("builtin-tls-168", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 168",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login168", false))));
        rules.add(new Rule("builtin-log-169", Severity.LOW, 40,
            "Built-in log telemetry signal 169",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny169", false))));
        rules.add(new Rule("builtin-http-170", Severity.HIGH, 45,
            "Built-in http telemetry signal 170",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin170", false))));
        rules.add(new Rule("builtin-http-171", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 171",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner171", false))));
        rules.add(new Rule("builtin-dns-172", Severity.LOW, 10,
            "Built-in dns telemetry signal 172",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip172", false))));
        rules.add(new Rule("builtin-tls-173", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 173",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login173", false))));
        rules.add(new Rule("builtin-log-174", Severity.LOW, 20,
            "Built-in log telemetry signal 174",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny174", false))));
        rules.add(new Rule("builtin-http-175", Severity.HIGH, 25,
            "Built-in http telemetry signal 175",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin175", false))));
        rules.add(new Rule("builtin-http-176", Severity.MEDIUM, 30,
            "Built-in http telemetry signal 176",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner176", false))));
        rules.add(new Rule("builtin-dns-177", Severity.LOW, 35,
            "Built-in dns telemetry signal 177",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip177", false))));
        rules.add(new Rule("builtin-tls-178", Severity.MEDIUM, 40,
            "Built-in tls telemetry signal 178",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login178", false))));
        rules.add(new Rule("builtin-log-179", Severity.LOW, 45,
            "Built-in log telemetry signal 179",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny179", false))));
        rules.add(new Rule("builtin-http-180", Severity.HIGH, 5,
            "Built-in http telemetry signal 180",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin180", false))));
        rules.add(new Rule("builtin-http-181", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 181",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner181", false))));
        rules.add(new Rule("builtin-dns-182", Severity.LOW, 15,
            "Built-in dns telemetry signal 182",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip182", false))));
        rules.add(new Rule("builtin-tls-183", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 183",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login183", false))));
        rules.add(new Rule("builtin-log-184", Severity.LOW, 25,
            "Built-in log telemetry signal 184",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny184", false))));
        rules.add(new Rule("builtin-http-185", Severity.HIGH, 30,
            "Built-in http telemetry signal 185",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin185", false))));
        rules.add(new Rule("builtin-http-186", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 186",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner186", false))));
        rules.add(new Rule("builtin-dns-187", Severity.LOW, 40,
            "Built-in dns telemetry signal 187",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip187", false))));
        rules.add(new Rule("builtin-tls-188", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 188",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login188", false))));
        rules.add(new Rule("builtin-log-189", Severity.LOW, 5,
            "Built-in log telemetry signal 189",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny189", false))));
        rules.add(new Rule("builtin-http-190", Severity.HIGH, 10,
            "Built-in http telemetry signal 190",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin190", false))));
        rules.add(new Rule("builtin-http-191", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 191",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner191", false))));
        rules.add(new Rule("builtin-dns-192", Severity.LOW, 20,
            "Built-in dns telemetry signal 192",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip192", false))));
        rules.add(new Rule("builtin-tls-193", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 193",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login193", false))));
        rules.add(new Rule("builtin-log-194", Severity.LOW, 30,
            "Built-in log telemetry signal 194",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny194", false))));
        rules.add(new Rule("builtin-http-195", Severity.HIGH, 35,
            "Built-in http telemetry signal 195",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin195", false))));
        rules.add(new Rule("builtin-http-196", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 196",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner196", false))));
        rules.add(new Rule("builtin-dns-197", Severity.LOW, 45,
            "Built-in dns telemetry signal 197",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip197", false))));
        rules.add(new Rule("builtin-tls-198", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 198",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login198", false))));
        rules.add(new Rule("builtin-log-199", Severity.LOW, 10,
            "Built-in log telemetry signal 199",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny199", false))));
        rules.add(new Rule("builtin-http-200", Severity.HIGH, 15,
            "Built-in http telemetry signal 200",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin200", false))));
        rules.add(new Rule("builtin-http-201", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 201",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner201", false))));
        rules.add(new Rule("builtin-dns-202", Severity.LOW, 25,
            "Built-in dns telemetry signal 202",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip202", false))));
        rules.add(new Rule("builtin-tls-203", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 203",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login203", false))));
        rules.add(new Rule("builtin-log-204", Severity.LOW, 35,
            "Built-in log telemetry signal 204",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny204", false))));
        rules.add(new Rule("builtin-http-205", Severity.HIGH, 40,
            "Built-in http telemetry signal 205",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin205", false))));
        rules.add(new Rule("builtin-http-206", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 206",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner206", false))));
        rules.add(new Rule("builtin-dns-207", Severity.LOW, 5,
            "Built-in dns telemetry signal 207",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip207", false))));
        rules.add(new Rule("builtin-tls-208", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 208",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login208", false))));
        rules.add(new Rule("builtin-log-209", Severity.LOW, 15,
            "Built-in log telemetry signal 209",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny209", false))));
        rules.add(new Rule("builtin-http-210", Severity.HIGH, 20,
            "Built-in http telemetry signal 210",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin210", false))));
        rules.add(new Rule("builtin-http-211", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 211",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner211", false))));
        rules.add(new Rule("builtin-dns-212", Severity.LOW, 30,
            "Built-in dns telemetry signal 212",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip212", false))));
        rules.add(new Rule("builtin-tls-213", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 213",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login213", false))));
        rules.add(new Rule("builtin-log-214", Severity.LOW, 40,
            "Built-in log telemetry signal 214",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny214", false))));
        rules.add(new Rule("builtin-http-215", Severity.HIGH, 45,
            "Built-in http telemetry signal 215",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin215", false))));
        rules.add(new Rule("builtin-http-216", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 216",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner216", false))));
        rules.add(new Rule("builtin-dns-217", Severity.LOW, 10,
            "Built-in dns telemetry signal 217",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip217", false))));
        rules.add(new Rule("builtin-tls-218", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 218",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login218", false))));
        rules.add(new Rule("builtin-log-219", Severity.LOW, 20,
            "Built-in log telemetry signal 219",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny219", false))));
        rules.add(new Rule("builtin-http-220", Severity.HIGH, 25,
            "Built-in http telemetry signal 220",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin220", false))));
        rules.add(new Rule("builtin-http-221", Severity.MEDIUM, 30,
            "Built-in http telemetry signal 221",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner221", false))));
        rules.add(new Rule("builtin-dns-222", Severity.LOW, 35,
            "Built-in dns telemetry signal 222",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip222", false))));
        rules.add(new Rule("builtin-tls-223", Severity.MEDIUM, 40,
            "Built-in tls telemetry signal 223",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login223", false))));
        rules.add(new Rule("builtin-log-224", Severity.LOW, 45,
            "Built-in log telemetry signal 224",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny224", false))));
        rules.add(new Rule("builtin-http-225", Severity.HIGH, 5,
            "Built-in http telemetry signal 225",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin225", false))));
        rules.add(new Rule("builtin-http-226", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 226",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner226", false))));
        rules.add(new Rule("builtin-dns-227", Severity.LOW, 15,
            "Built-in dns telemetry signal 227",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip227", false))));
        rules.add(new Rule("builtin-tls-228", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 228",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login228", false))));
        rules.add(new Rule("builtin-log-229", Severity.LOW, 25,
            "Built-in log telemetry signal 229",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny229", false))));
        rules.add(new Rule("builtin-http-230", Severity.HIGH, 30,
            "Built-in http telemetry signal 230",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin230", false))));
        rules.add(new Rule("builtin-http-231", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 231",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner231", false))));
        rules.add(new Rule("builtin-dns-232", Severity.LOW, 40,
            "Built-in dns telemetry signal 232",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip232", false))));
        rules.add(new Rule("builtin-tls-233", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 233",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login233", false))));
        rules.add(new Rule("builtin-log-234", Severity.LOW, 5,
            "Built-in log telemetry signal 234",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny234", false))));
        rules.add(new Rule("builtin-http-235", Severity.HIGH, 10,
            "Built-in http telemetry signal 235",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin235", false))));
        rules.add(new Rule("builtin-http-236", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 236",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner236", false))));
        rules.add(new Rule("builtin-dns-237", Severity.LOW, 20,
            "Built-in dns telemetry signal 237",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip237", false))));
        rules.add(new Rule("builtin-tls-238", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 238",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login238", false))));
        rules.add(new Rule("builtin-log-239", Severity.LOW, 30,
            "Built-in log telemetry signal 239",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny239", false))));
        rules.add(new Rule("builtin-http-240", Severity.HIGH, 35,
            "Built-in http telemetry signal 240",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin240", false))));
        rules.add(new Rule("builtin-http-241", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 241",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner241", false))));
        rules.add(new Rule("builtin-dns-242", Severity.LOW, 45,
            "Built-in dns telemetry signal 242",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip242", false))));
        rules.add(new Rule("builtin-tls-243", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 243",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login243", false))));
        rules.add(new Rule("builtin-log-244", Severity.LOW, 10,
            "Built-in log telemetry signal 244",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny244", false))));
        rules.add(new Rule("builtin-http-245", Severity.HIGH, 15,
            "Built-in http telemetry signal 245",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin245", false))));
        rules.add(new Rule("builtin-http-246", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 246",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner246", false))));
        rules.add(new Rule("builtin-dns-247", Severity.LOW, 25,
            "Built-in dns telemetry signal 247",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip247", false))));
        rules.add(new Rule("builtin-tls-248", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 248",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login248", false))));
        rules.add(new Rule("builtin-log-249", Severity.LOW, 35,
            "Built-in log telemetry signal 249",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny249", false))));
        rules.add(new Rule("builtin-http-250", Severity.HIGH, 40,
            "Built-in http telemetry signal 250",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin250", false))));
        rules.add(new Rule("builtin-http-251", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 251",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner251", false))));
        rules.add(new Rule("builtin-dns-252", Severity.LOW, 5,
            "Built-in dns telemetry signal 252",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip252", false))));
        rules.add(new Rule("builtin-tls-253", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 253",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login253", false))));
        rules.add(new Rule("builtin-log-254", Severity.LOW, 15,
            "Built-in log telemetry signal 254",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny254", false))));
        rules.add(new Rule("builtin-http-255", Severity.HIGH, 20,
            "Built-in http telemetry signal 255",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin255", false))));
        rules.add(new Rule("builtin-http-256", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 256",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner256", false))));
        rules.add(new Rule("builtin-dns-257", Severity.LOW, 30,
            "Built-in dns telemetry signal 257",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip257", false))));
        rules.add(new Rule("builtin-tls-258", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 258",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login258", false))));
        rules.add(new Rule("builtin-log-259", Severity.LOW, 40,
            "Built-in log telemetry signal 259",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny259", false))));
        rules.add(new Rule("builtin-http-260", Severity.HIGH, 45,
            "Built-in http telemetry signal 260",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin260", false))));
        rules.add(new Rule("builtin-http-261", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 261",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner261", false))));
        rules.add(new Rule("builtin-dns-262", Severity.LOW, 10,
            "Built-in dns telemetry signal 262",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip262", false))));
        rules.add(new Rule("builtin-tls-263", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 263",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login263", false))));
        rules.add(new Rule("builtin-log-264", Severity.LOW, 20,
            "Built-in log telemetry signal 264",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny264", false))));
        rules.add(new Rule("builtin-http-265", Severity.HIGH, 25,
            "Built-in http telemetry signal 265",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin265", false))));
        rules.add(new Rule("builtin-http-266", Severity.MEDIUM, 30,
            "Built-in http telemetry signal 266",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner266", false))));
        rules.add(new Rule("builtin-dns-267", Severity.LOW, 35,
            "Built-in dns telemetry signal 267",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip267", false))));
        rules.add(new Rule("builtin-tls-268", Severity.MEDIUM, 40,
            "Built-in tls telemetry signal 268",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login268", false))));
        rules.add(new Rule("builtin-log-269", Severity.LOW, 45,
            "Built-in log telemetry signal 269",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny269", false))));
        rules.add(new Rule("builtin-http-270", Severity.HIGH, 5,
            "Built-in http telemetry signal 270",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin270", false))));
        rules.add(new Rule("builtin-http-271", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 271",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner271", false))));
        rules.add(new Rule("builtin-dns-272", Severity.LOW, 15,
            "Built-in dns telemetry signal 272",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip272", false))));
        rules.add(new Rule("builtin-tls-273", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 273",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login273", false))));
        rules.add(new Rule("builtin-log-274", Severity.LOW, 25,
            "Built-in log telemetry signal 274",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny274", false))));
        rules.add(new Rule("builtin-http-275", Severity.HIGH, 30,
            "Built-in http telemetry signal 275",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin275", false))));
        rules.add(new Rule("builtin-http-276", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 276",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner276", false))));
        rules.add(new Rule("builtin-dns-277", Severity.LOW, 40,
            "Built-in dns telemetry signal 277",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip277", false))));
        rules.add(new Rule("builtin-tls-278", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 278",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login278", false))));
        rules.add(new Rule("builtin-log-279", Severity.LOW, 5,
            "Built-in log telemetry signal 279",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny279", false))));
        rules.add(new Rule("builtin-http-280", Severity.HIGH, 10,
            "Built-in http telemetry signal 280",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin280", false))));
        rules.add(new Rule("builtin-http-281", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 281",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner281", false))));
        rules.add(new Rule("builtin-dns-282", Severity.LOW, 20,
            "Built-in dns telemetry signal 282",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip282", false))));
        rules.add(new Rule("builtin-tls-283", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 283",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login283", false))));
        rules.add(new Rule("builtin-log-284", Severity.LOW, 30,
            "Built-in log telemetry signal 284",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny284", false))));
        rules.add(new Rule("builtin-http-285", Severity.HIGH, 35,
            "Built-in http telemetry signal 285",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin285", false))));
        rules.add(new Rule("builtin-http-286", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 286",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner286", false))));
        rules.add(new Rule("builtin-dns-287", Severity.LOW, 45,
            "Built-in dns telemetry signal 287",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip287", false))));
        rules.add(new Rule("builtin-tls-288", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 288",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login288", false))));
        rules.add(new Rule("builtin-log-289", Severity.LOW, 10,
            "Built-in log telemetry signal 289",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny289", false))));
        rules.add(new Rule("builtin-http-290", Severity.HIGH, 15,
            "Built-in http telemetry signal 290",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin290", false))));
        rules.add(new Rule("builtin-http-291", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 291",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner291", false))));
        rules.add(new Rule("builtin-dns-292", Severity.LOW, 25,
            "Built-in dns telemetry signal 292",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip292", false))));
        rules.add(new Rule("builtin-tls-293", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 293",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login293", false))));
        rules.add(new Rule("builtin-log-294", Severity.LOW, 35,
            "Built-in log telemetry signal 294",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny294", false))));
        rules.add(new Rule("builtin-http-295", Severity.HIGH, 40,
            "Built-in http telemetry signal 295",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin295", false))));
        rules.add(new Rule("builtin-http-296", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 296",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner296", false))));
        rules.add(new Rule("builtin-dns-297", Severity.LOW, 5,
            "Built-in dns telemetry signal 297",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip297", false))));
        rules.add(new Rule("builtin-tls-298", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 298",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login298", false))));
        rules.add(new Rule("builtin-log-299", Severity.LOW, 15,
            "Built-in log telemetry signal 299",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny299", false))));
        rules.add(new Rule("builtin-http-300", Severity.HIGH, 20,
            "Built-in http telemetry signal 300",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin300", false))));
        rules.add(new Rule("builtin-http-301", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 301",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner301", false))));
        rules.add(new Rule("builtin-dns-302", Severity.LOW, 30,
            "Built-in dns telemetry signal 302",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip302", false))));
        rules.add(new Rule("builtin-tls-303", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 303",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login303", false))));
        rules.add(new Rule("builtin-log-304", Severity.LOW, 40,
            "Built-in log telemetry signal 304",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny304", false))));
        rules.add(new Rule("builtin-http-305", Severity.HIGH, 45,
            "Built-in http telemetry signal 305",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin305", false))));
        rules.add(new Rule("builtin-http-306", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 306",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner306", false))));
        rules.add(new Rule("builtin-dns-307", Severity.LOW, 10,
            "Built-in dns telemetry signal 307",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip307", false))));
        rules.add(new Rule("builtin-tls-308", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 308",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login308", false))));
        rules.add(new Rule("builtin-log-309", Severity.LOW, 20,
            "Built-in log telemetry signal 309",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny309", false))));
        rules.add(new Rule("builtin-http-310", Severity.HIGH, 25,
            "Built-in http telemetry signal 310",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin310", false))));
        rules.add(new Rule("builtin-http-311", Severity.MEDIUM, 30,
            "Built-in http telemetry signal 311",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner311", false))));
        rules.add(new Rule("builtin-dns-312", Severity.LOW, 35,
            "Built-in dns telemetry signal 312",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip312", false))));
        rules.add(new Rule("builtin-tls-313", Severity.MEDIUM, 40,
            "Built-in tls telemetry signal 313",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login313", false))));
        rules.add(new Rule("builtin-log-314", Severity.LOW, 45,
            "Built-in log telemetry signal 314",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny314", false))));
        rules.add(new Rule("builtin-http-315", Severity.HIGH, 5,
            "Built-in http telemetry signal 315",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin315", false))));
        rules.add(new Rule("builtin-http-316", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 316",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner316", false))));
        rules.add(new Rule("builtin-dns-317", Severity.LOW, 15,
            "Built-in dns telemetry signal 317",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip317", false))));
        rules.add(new Rule("builtin-tls-318", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 318",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login318", false))));
        rules.add(new Rule("builtin-log-319", Severity.LOW, 25,
            "Built-in log telemetry signal 319",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny319", false))));
        rules.add(new Rule("builtin-http-320", Severity.HIGH, 30,
            "Built-in http telemetry signal 320",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin320", false))));
        rules.add(new Rule("builtin-http-321", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 321",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner321", false))));
        rules.add(new Rule("builtin-dns-322", Severity.LOW, 40,
            "Built-in dns telemetry signal 322",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip322", false))));
        rules.add(new Rule("builtin-tls-323", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 323",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login323", false))));
        rules.add(new Rule("builtin-log-324", Severity.LOW, 5,
            "Built-in log telemetry signal 324",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny324", false))));
        rules.add(new Rule("builtin-http-325", Severity.HIGH, 10,
            "Built-in http telemetry signal 325",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin325", false))));
        rules.add(new Rule("builtin-http-326", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 326",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner326", false))));
        rules.add(new Rule("builtin-dns-327", Severity.LOW, 20,
            "Built-in dns telemetry signal 327",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip327", false))));
        rules.add(new Rule("builtin-tls-328", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 328",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login328", false))));
        rules.add(new Rule("builtin-log-329", Severity.LOW, 30,
            "Built-in log telemetry signal 329",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny329", false))));
        rules.add(new Rule("builtin-http-330", Severity.HIGH, 35,
            "Built-in http telemetry signal 330",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin330", false))));
        rules.add(new Rule("builtin-http-331", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 331",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner331", false))));
        rules.add(new Rule("builtin-dns-332", Severity.LOW, 45,
            "Built-in dns telemetry signal 332",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip332", false))));
        rules.add(new Rule("builtin-tls-333", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 333",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login333", false))));
        rules.add(new Rule("builtin-log-334", Severity.LOW, 10,
            "Built-in log telemetry signal 334",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny334", false))));
        rules.add(new Rule("builtin-http-335", Severity.HIGH, 15,
            "Built-in http telemetry signal 335",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin335", false))));
        rules.add(new Rule("builtin-http-336", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 336",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner336", false))));
        rules.add(new Rule("builtin-dns-337", Severity.LOW, 25,
            "Built-in dns telemetry signal 337",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip337", false))));
        rules.add(new Rule("builtin-tls-338", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 338",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login338", false))));
        rules.add(new Rule("builtin-log-339", Severity.LOW, 35,
            "Built-in log telemetry signal 339",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny339", false))));
        rules.add(new Rule("builtin-http-340", Severity.HIGH, 40,
            "Built-in http telemetry signal 340",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin340", false))));
        rules.add(new Rule("builtin-http-341", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 341",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner341", false))));
        rules.add(new Rule("builtin-dns-342", Severity.LOW, 5,
            "Built-in dns telemetry signal 342",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip342", false))));
        rules.add(new Rule("builtin-tls-343", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 343",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login343", false))));
        rules.add(new Rule("builtin-log-344", Severity.LOW, 15,
            "Built-in log telemetry signal 344",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny344", false))));
        rules.add(new Rule("builtin-http-345", Severity.HIGH, 20,
            "Built-in http telemetry signal 345",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin345", false))));
        rules.add(new Rule("builtin-http-346", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 346",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner346", false))));
        rules.add(new Rule("builtin-dns-347", Severity.LOW, 30,
            "Built-in dns telemetry signal 347",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip347", false))));
        rules.add(new Rule("builtin-tls-348", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 348",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login348", false))));
        rules.add(new Rule("builtin-log-349", Severity.LOW, 40,
            "Built-in log telemetry signal 349",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny349", false))));
        rules.add(new Rule("builtin-http-350", Severity.HIGH, 45,
            "Built-in http telemetry signal 350",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin350", false))));
        rules.add(new Rule("builtin-http-351", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 351",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner351", false))));
        rules.add(new Rule("builtin-dns-352", Severity.LOW, 10,
            "Built-in dns telemetry signal 352",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip352", false))));
        rules.add(new Rule("builtin-tls-353", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 353",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login353", false))));
        rules.add(new Rule("builtin-log-354", Severity.LOW, 20,
            "Built-in log telemetry signal 354",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny354", false))));
        rules.add(new Rule("builtin-http-355", Severity.HIGH, 25,
            "Built-in http telemetry signal 355",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin355", false))));
        rules.add(new Rule("builtin-http-356", Severity.MEDIUM, 30,
            "Built-in http telemetry signal 356",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner356", false))));
        rules.add(new Rule("builtin-dns-357", Severity.LOW, 35,
            "Built-in dns telemetry signal 357",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip357", false))));
        rules.add(new Rule("builtin-tls-358", Severity.MEDIUM, 40,
            "Built-in tls telemetry signal 358",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login358", false))));
        rules.add(new Rule("builtin-log-359", Severity.LOW, 45,
            "Built-in log telemetry signal 359",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny359", false))));
        rules.add(new Rule("builtin-http-360", Severity.HIGH, 5,
            "Built-in http telemetry signal 360",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin360", false))));
        rules.add(new Rule("builtin-http-361", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 361",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner361", false))));
        rules.add(new Rule("builtin-dns-362", Severity.LOW, 15,
            "Built-in dns telemetry signal 362",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip362", false))));
        rules.add(new Rule("builtin-tls-363", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 363",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login363", false))));
        rules.add(new Rule("builtin-log-364", Severity.LOW, 25,
            "Built-in log telemetry signal 364",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny364", false))));
        rules.add(new Rule("builtin-http-365", Severity.HIGH, 30,
            "Built-in http telemetry signal 365",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin365", false))));
        rules.add(new Rule("builtin-http-366", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 366",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner366", false))));
        rules.add(new Rule("builtin-dns-367", Severity.LOW, 40,
            "Built-in dns telemetry signal 367",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip367", false))));
        rules.add(new Rule("builtin-tls-368", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 368",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login368", false))));
        rules.add(new Rule("builtin-log-369", Severity.LOW, 5,
            "Built-in log telemetry signal 369",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny369", false))));
        rules.add(new Rule("builtin-http-370", Severity.HIGH, 10,
            "Built-in http telemetry signal 370",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin370", false))));
        rules.add(new Rule("builtin-http-371", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 371",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner371", false))));
        rules.add(new Rule("builtin-dns-372", Severity.LOW, 20,
            "Built-in dns telemetry signal 372",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip372", false))));
        rules.add(new Rule("builtin-tls-373", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 373",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login373", false))));
        rules.add(new Rule("builtin-log-374", Severity.LOW, 30,
            "Built-in log telemetry signal 374",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny374", false))));
        rules.add(new Rule("builtin-http-375", Severity.HIGH, 35,
            "Built-in http telemetry signal 375",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin375", false))));
        rules.add(new Rule("builtin-http-376", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 376",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner376", false))));
        rules.add(new Rule("builtin-dns-377", Severity.LOW, 45,
            "Built-in dns telemetry signal 377",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip377", false))));
        rules.add(new Rule("builtin-tls-378", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 378",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login378", false))));
        rules.add(new Rule("builtin-log-379", Severity.LOW, 10,
            "Built-in log telemetry signal 379",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny379", false))));
        rules.add(new Rule("builtin-http-380", Severity.HIGH, 15,
            "Built-in http telemetry signal 380",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin380", false))));
        rules.add(new Rule("builtin-http-381", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 381",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner381", false))));
        rules.add(new Rule("builtin-dns-382", Severity.LOW, 25,
            "Built-in dns telemetry signal 382",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip382", false))));
        rules.add(new Rule("builtin-tls-383", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 383",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login383", false))));
        rules.add(new Rule("builtin-log-384", Severity.LOW, 35,
            "Built-in log telemetry signal 384",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny384", false))));
        rules.add(new Rule("builtin-http-385", Severity.HIGH, 40,
            "Built-in http telemetry signal 385",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin385", false))));
        rules.add(new Rule("builtin-http-386", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 386",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner386", false))));
        rules.add(new Rule("builtin-dns-387", Severity.LOW, 5,
            "Built-in dns telemetry signal 387",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip387", false))));
        rules.add(new Rule("builtin-tls-388", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 388",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login388", false))));
        rules.add(new Rule("builtin-log-389", Severity.LOW, 15,
            "Built-in log telemetry signal 389",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny389", false))));
        rules.add(new Rule("builtin-http-390", Severity.HIGH, 20,
            "Built-in http telemetry signal 390",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin390", false))));
        rules.add(new Rule("builtin-http-391", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 391",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner391", false))));
        rules.add(new Rule("builtin-dns-392", Severity.LOW, 30,
            "Built-in dns telemetry signal 392",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip392", false))));
        rules.add(new Rule("builtin-tls-393", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 393",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login393", false))));
        rules.add(new Rule("builtin-log-394", Severity.LOW, 40,
            "Built-in log telemetry signal 394",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny394", false))));
        rules.add(new Rule("builtin-http-395", Severity.HIGH, 45,
            "Built-in http telemetry signal 395",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin395", false))));
        rules.add(new Rule("builtin-http-396", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 396",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner396", false))));
        rules.add(new Rule("builtin-dns-397", Severity.LOW, 10,
            "Built-in dns telemetry signal 397",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip397", false))));
        rules.add(new Rule("builtin-tls-398", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 398",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login398", false))));
        rules.add(new Rule("builtin-log-399", Severity.LOW, 20,
            "Built-in log telemetry signal 399",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny399", false))));
        rules.add(new Rule("builtin-http-400", Severity.HIGH, 25,
            "Built-in http telemetry signal 400",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin400", false))));
        rules.add(new Rule("builtin-http-401", Severity.MEDIUM, 30,
            "Built-in http telemetry signal 401",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner401", false))));
        rules.add(new Rule("builtin-dns-402", Severity.LOW, 35,
            "Built-in dns telemetry signal 402",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip402", false))));
        rules.add(new Rule("builtin-tls-403", Severity.MEDIUM, 40,
            "Built-in tls telemetry signal 403",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login403", false))));
        rules.add(new Rule("builtin-log-404", Severity.LOW, 45,
            "Built-in log telemetry signal 404",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny404", false))));
        rules.add(new Rule("builtin-http-405", Severity.HIGH, 5,
            "Built-in http telemetry signal 405",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin405", false))));
        rules.add(new Rule("builtin-http-406", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 406",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner406", false))));
        rules.add(new Rule("builtin-dns-407", Severity.LOW, 15,
            "Built-in dns telemetry signal 407",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip407", false))));
        rules.add(new Rule("builtin-tls-408", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 408",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login408", false))));
        rules.add(new Rule("builtin-log-409", Severity.LOW, 25,
            "Built-in log telemetry signal 409",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny409", false))));
        rules.add(new Rule("builtin-http-410", Severity.HIGH, 30,
            "Built-in http telemetry signal 410",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin410", false))));
        rules.add(new Rule("builtin-http-411", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 411",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner411", false))));
        rules.add(new Rule("builtin-dns-412", Severity.LOW, 40,
            "Built-in dns telemetry signal 412",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip412", false))));
        rules.add(new Rule("builtin-tls-413", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 413",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login413", false))));
        rules.add(new Rule("builtin-log-414", Severity.LOW, 5,
            "Built-in log telemetry signal 414",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny414", false))));
        rules.add(new Rule("builtin-http-415", Severity.HIGH, 10,
            "Built-in http telemetry signal 415",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin415", false))));
        rules.add(new Rule("builtin-http-416", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 416",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner416", false))));
        rules.add(new Rule("builtin-dns-417", Severity.LOW, 20,
            "Built-in dns telemetry signal 417",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip417", false))));
        rules.add(new Rule("builtin-tls-418", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 418",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login418", false))));
        rules.add(new Rule("builtin-log-419", Severity.LOW, 30,
            "Built-in log telemetry signal 419",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny419", false))));
        rules.add(new Rule("builtin-http-420", Severity.HIGH, 35,
            "Built-in http telemetry signal 420",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin420", false))));
        rules.add(new Rule("builtin-http-421", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 421",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner421", false))));
        rules.add(new Rule("builtin-dns-422", Severity.LOW, 45,
            "Built-in dns telemetry signal 422",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip422", false))));
        rules.add(new Rule("builtin-tls-423", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 423",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login423", false))));
        rules.add(new Rule("builtin-log-424", Severity.LOW, 10,
            "Built-in log telemetry signal 424",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny424", false))));
        rules.add(new Rule("builtin-http-425", Severity.HIGH, 15,
            "Built-in http telemetry signal 425",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin425", false))));
        rules.add(new Rule("builtin-http-426", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 426",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner426", false))));
        rules.add(new Rule("builtin-dns-427", Severity.LOW, 25,
            "Built-in dns telemetry signal 427",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip427", false))));
        rules.add(new Rule("builtin-tls-428", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 428",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login428", false))));
        rules.add(new Rule("builtin-log-429", Severity.LOW, 35,
            "Built-in log telemetry signal 429",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny429", false))));
        rules.add(new Rule("builtin-http-430", Severity.HIGH, 40,
            "Built-in http telemetry signal 430",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin430", false))));
        rules.add(new Rule("builtin-http-431", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 431",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner431", false))));
        rules.add(new Rule("builtin-dns-432", Severity.LOW, 5,
            "Built-in dns telemetry signal 432",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip432", false))));
        rules.add(new Rule("builtin-tls-433", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 433",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login433", false))));
        rules.add(new Rule("builtin-log-434", Severity.LOW, 15,
            "Built-in log telemetry signal 434",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny434", false))));
        rules.add(new Rule("builtin-http-435", Severity.HIGH, 20,
            "Built-in http telemetry signal 435",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin435", false))));
        rules.add(new Rule("builtin-http-436", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 436",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner436", false))));
        rules.add(new Rule("builtin-dns-437", Severity.LOW, 30,
            "Built-in dns telemetry signal 437",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip437", false))));
        rules.add(new Rule("builtin-tls-438", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 438",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login438", false))));
        rules.add(new Rule("builtin-log-439", Severity.LOW, 40,
            "Built-in log telemetry signal 439",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny439", false))));
        rules.add(new Rule("builtin-http-440", Severity.HIGH, 45,
            "Built-in http telemetry signal 440",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin440", false))));
        rules.add(new Rule("builtin-http-441", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 441",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner441", false))));
        rules.add(new Rule("builtin-dns-442", Severity.LOW, 10,
            "Built-in dns telemetry signal 442",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip442", false))));
        rules.add(new Rule("builtin-tls-443", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 443",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login443", false))));
        rules.add(new Rule("builtin-log-444", Severity.LOW, 20,
            "Built-in log telemetry signal 444",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny444", false))));
        rules.add(new Rule("builtin-http-445", Severity.HIGH, 25,
            "Built-in http telemetry signal 445",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin445", false))));
        rules.add(new Rule("builtin-http-446", Severity.MEDIUM, 30,
            "Built-in http telemetry signal 446",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner446", false))));
        rules.add(new Rule("builtin-dns-447", Severity.LOW, 35,
            "Built-in dns telemetry signal 447",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip447", false))));
        rules.add(new Rule("builtin-tls-448", Severity.MEDIUM, 40,
            "Built-in tls telemetry signal 448",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login448", false))));
        rules.add(new Rule("builtin-log-449", Severity.LOW, 45,
            "Built-in log telemetry signal 449",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny449", false))));
        rules.add(new Rule("builtin-http-450", Severity.HIGH, 5,
            "Built-in http telemetry signal 450",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin450", false))));
        rules.add(new Rule("builtin-http-451", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 451",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner451", false))));
        rules.add(new Rule("builtin-dns-452", Severity.LOW, 15,
            "Built-in dns telemetry signal 452",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip452", false))));
        rules.add(new Rule("builtin-tls-453", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 453",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login453", false))));
        rules.add(new Rule("builtin-log-454", Severity.LOW, 25,
            "Built-in log telemetry signal 454",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny454", false))));
        rules.add(new Rule("builtin-http-455", Severity.HIGH, 30,
            "Built-in http telemetry signal 455",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin455", false))));
        rules.add(new Rule("builtin-http-456", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 456",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner456", false))));
        rules.add(new Rule("builtin-dns-457", Severity.LOW, 40,
            "Built-in dns telemetry signal 457",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip457", false))));
        rules.add(new Rule("builtin-tls-458", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 458",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login458", false))));
        rules.add(new Rule("builtin-log-459", Severity.LOW, 5,
            "Built-in log telemetry signal 459",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny459", false))));
        rules.add(new Rule("builtin-http-460", Severity.HIGH, 10,
            "Built-in http telemetry signal 460",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin460", false))));
        rules.add(new Rule("builtin-http-461", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 461",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner461", false))));
        rules.add(new Rule("builtin-dns-462", Severity.LOW, 20,
            "Built-in dns telemetry signal 462",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip462", false))));
        rules.add(new Rule("builtin-tls-463", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 463",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login463", false))));
        rules.add(new Rule("builtin-log-464", Severity.LOW, 30,
            "Built-in log telemetry signal 464",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny464", false))));
        rules.add(new Rule("builtin-http-465", Severity.HIGH, 35,
            "Built-in http telemetry signal 465",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin465", false))));
        rules.add(new Rule("builtin-http-466", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 466",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner466", false))));
        rules.add(new Rule("builtin-dns-467", Severity.LOW, 45,
            "Built-in dns telemetry signal 467",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip467", false))));
        rules.add(new Rule("builtin-tls-468", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 468",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login468", false))));
        rules.add(new Rule("builtin-log-469", Severity.LOW, 10,
            "Built-in log telemetry signal 469",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny469", false))));
        rules.add(new Rule("builtin-http-470", Severity.HIGH, 15,
            "Built-in http telemetry signal 470",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin470", false))));
        rules.add(new Rule("builtin-http-471", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 471",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner471", false))));
        rules.add(new Rule("builtin-dns-472", Severity.LOW, 25,
            "Built-in dns telemetry signal 472",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip472", false))));
        rules.add(new Rule("builtin-tls-473", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 473",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login473", false))));
        rules.add(new Rule("builtin-log-474", Severity.LOW, 35,
            "Built-in log telemetry signal 474",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny474", false))));
        rules.add(new Rule("builtin-http-475", Severity.HIGH, 40,
            "Built-in http telemetry signal 475",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin475", false))));
        rules.add(new Rule("builtin-http-476", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 476",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner476", false))));
        rules.add(new Rule("builtin-dns-477", Severity.LOW, 5,
            "Built-in dns telemetry signal 477",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip477", false))));
        rules.add(new Rule("builtin-tls-478", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 478",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login478", false))));
        rules.add(new Rule("builtin-log-479", Severity.LOW, 15,
            "Built-in log telemetry signal 479",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny479", false))));
        rules.add(new Rule("builtin-http-480", Severity.HIGH, 20,
            "Built-in http telemetry signal 480",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin480", false))));
        rules.add(new Rule("builtin-http-481", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 481",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner481", false))));
        rules.add(new Rule("builtin-dns-482", Severity.LOW, 30,
            "Built-in dns telemetry signal 482",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip482", false))));
        rules.add(new Rule("builtin-tls-483", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 483",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login483", false))));
        rules.add(new Rule("builtin-log-484", Severity.LOW, 40,
            "Built-in log telemetry signal 484",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny484", false))));
        rules.add(new Rule("builtin-http-485", Severity.HIGH, 45,
            "Built-in http telemetry signal 485",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin485", false))));
        rules.add(new Rule("builtin-http-486", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 486",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner486", false))));
        rules.add(new Rule("builtin-dns-487", Severity.LOW, 10,
            "Built-in dns telemetry signal 487",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip487", false))));
        rules.add(new Rule("builtin-tls-488", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 488",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login488", false))));
        rules.add(new Rule("builtin-log-489", Severity.LOW, 20,
            "Built-in log telemetry signal 489",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny489", false))));
        rules.add(new Rule("builtin-http-490", Severity.HIGH, 25,
            "Built-in http telemetry signal 490",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin490", false))));
        rules.add(new Rule("builtin-http-491", Severity.MEDIUM, 30,
            "Built-in http telemetry signal 491",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner491", false))));
        rules.add(new Rule("builtin-dns-492", Severity.LOW, 35,
            "Built-in dns telemetry signal 492",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip492", false))));
        rules.add(new Rule("builtin-tls-493", Severity.MEDIUM, 40,
            "Built-in tls telemetry signal 493",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login493", false))));
        rules.add(new Rule("builtin-log-494", Severity.LOW, 45,
            "Built-in log telemetry signal 494",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny494", false))));
        rules.add(new Rule("builtin-http-495", Severity.HIGH, 5,
            "Built-in http telemetry signal 495",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin495", false))));
        rules.add(new Rule("builtin-http-496", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 496",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner496", false))));
        rules.add(new Rule("builtin-dns-497", Severity.LOW, 15,
            "Built-in dns telemetry signal 497",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip497", false))));
        rules.add(new Rule("builtin-tls-498", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 498",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login498", false))));
        rules.add(new Rule("builtin-log-499", Severity.LOW, 25,
            "Built-in log telemetry signal 499",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny499", false))));
        rules.add(new Rule("builtin-http-500", Severity.HIGH, 30,
            "Built-in http telemetry signal 500",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin500", false))));
        rules.add(new Rule("builtin-http-501", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 501",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner501", false))));
        rules.add(new Rule("builtin-dns-502", Severity.LOW, 40,
            "Built-in dns telemetry signal 502",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip502", false))));
        rules.add(new Rule("builtin-tls-503", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 503",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login503", false))));
        rules.add(new Rule("builtin-log-504", Severity.LOW, 5,
            "Built-in log telemetry signal 504",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny504", false))));
        rules.add(new Rule("builtin-http-505", Severity.HIGH, 10,
            "Built-in http telemetry signal 505",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin505", false))));
        rules.add(new Rule("builtin-http-506", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 506",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner506", false))));
        rules.add(new Rule("builtin-dns-507", Severity.LOW, 20,
            "Built-in dns telemetry signal 507",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip507", false))));
        rules.add(new Rule("builtin-tls-508", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 508",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login508", false))));
        rules.add(new Rule("builtin-log-509", Severity.LOW, 30,
            "Built-in log telemetry signal 509",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny509", false))));
        rules.add(new Rule("builtin-http-510", Severity.HIGH, 35,
            "Built-in http telemetry signal 510",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin510", false))));
        rules.add(new Rule("builtin-http-511", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 511",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner511", false))));
        rules.add(new Rule("builtin-dns-512", Severity.LOW, 45,
            "Built-in dns telemetry signal 512",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip512", false))));
        rules.add(new Rule("builtin-tls-513", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 513",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login513", false))));
        rules.add(new Rule("builtin-log-514", Severity.LOW, 10,
            "Built-in log telemetry signal 514",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny514", false))));
        rules.add(new Rule("builtin-http-515", Severity.HIGH, 15,
            "Built-in http telemetry signal 515",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin515", false))));
        rules.add(new Rule("builtin-http-516", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 516",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner516", false))));
        rules.add(new Rule("builtin-dns-517", Severity.LOW, 25,
            "Built-in dns telemetry signal 517",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip517", false))));
        rules.add(new Rule("builtin-tls-518", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 518",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login518", false))));
        rules.add(new Rule("builtin-log-519", Severity.LOW, 35,
            "Built-in log telemetry signal 519",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny519", false))));
        rules.add(new Rule("builtin-http-520", Severity.HIGH, 40,
            "Built-in http telemetry signal 520",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin520", false))));
        rules.add(new Rule("builtin-http-521", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 521",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner521", false))));
        rules.add(new Rule("builtin-dns-522", Severity.LOW, 5,
            "Built-in dns telemetry signal 522",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip522", false))));
        rules.add(new Rule("builtin-tls-523", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 523",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login523", false))));
        rules.add(new Rule("builtin-log-524", Severity.LOW, 15,
            "Built-in log telemetry signal 524",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny524", false))));
        rules.add(new Rule("builtin-http-525", Severity.HIGH, 20,
            "Built-in http telemetry signal 525",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin525", false))));
        rules.add(new Rule("builtin-http-526", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 526",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner526", false))));
        rules.add(new Rule("builtin-dns-527", Severity.LOW, 30,
            "Built-in dns telemetry signal 527",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip527", false))));
        rules.add(new Rule("builtin-tls-528", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 528",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login528", false))));
        rules.add(new Rule("builtin-log-529", Severity.LOW, 40,
            "Built-in log telemetry signal 529",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny529", false))));
        rules.add(new Rule("builtin-http-530", Severity.HIGH, 45,
            "Built-in http telemetry signal 530",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin530", false))));
        rules.add(new Rule("builtin-http-531", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 531",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner531", false))));
        rules.add(new Rule("builtin-dns-532", Severity.LOW, 10,
            "Built-in dns telemetry signal 532",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip532", false))));
        rules.add(new Rule("builtin-tls-533", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 533",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login533", false))));
        rules.add(new Rule("builtin-log-534", Severity.LOW, 20,
            "Built-in log telemetry signal 534",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny534", false))));
        rules.add(new Rule("builtin-http-535", Severity.HIGH, 25,
            "Built-in http telemetry signal 535",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin535", false))));
        rules.add(new Rule("builtin-http-536", Severity.MEDIUM, 30,
            "Built-in http telemetry signal 536",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner536", false))));
        rules.add(new Rule("builtin-dns-537", Severity.LOW, 35,
            "Built-in dns telemetry signal 537",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip537", false))));
        rules.add(new Rule("builtin-tls-538", Severity.MEDIUM, 40,
            "Built-in tls telemetry signal 538",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login538", false))));
        rules.add(new Rule("builtin-log-539", Severity.LOW, 45,
            "Built-in log telemetry signal 539",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny539", false))));
        rules.add(new Rule("builtin-http-540", Severity.HIGH, 5,
            "Built-in http telemetry signal 540",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin540", false))));
        rules.add(new Rule("builtin-http-541", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 541",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner541", false))));
        rules.add(new Rule("builtin-dns-542", Severity.LOW, 15,
            "Built-in dns telemetry signal 542",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip542", false))));
        rules.add(new Rule("builtin-tls-543", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 543",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login543", false))));
        rules.add(new Rule("builtin-log-544", Severity.LOW, 25,
            "Built-in log telemetry signal 544",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny544", false))));
        rules.add(new Rule("builtin-http-545", Severity.HIGH, 30,
            "Built-in http telemetry signal 545",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin545", false))));
        rules.add(new Rule("builtin-http-546", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 546",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner546", false))));
        rules.add(new Rule("builtin-dns-547", Severity.LOW, 40,
            "Built-in dns telemetry signal 547",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip547", false))));
        rules.add(new Rule("builtin-tls-548", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 548",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login548", false))));
        rules.add(new Rule("builtin-log-549", Severity.LOW, 5,
            "Built-in log telemetry signal 549",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny549", false))));
        rules.add(new Rule("builtin-http-550", Severity.HIGH, 10,
            "Built-in http telemetry signal 550",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin550", false))));
        rules.add(new Rule("builtin-http-551", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 551",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner551", false))));
        rules.add(new Rule("builtin-dns-552", Severity.LOW, 20,
            "Built-in dns telemetry signal 552",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip552", false))));
        rules.add(new Rule("builtin-tls-553", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 553",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login553", false))));
        rules.add(new Rule("builtin-log-554", Severity.LOW, 30,
            "Built-in log telemetry signal 554",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny554", false))));
        rules.add(new Rule("builtin-http-555", Severity.HIGH, 35,
            "Built-in http telemetry signal 555",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin555", false))));
        rules.add(new Rule("builtin-http-556", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 556",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner556", false))));
        rules.add(new Rule("builtin-dns-557", Severity.LOW, 45,
            "Built-in dns telemetry signal 557",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip557", false))));
        rules.add(new Rule("builtin-tls-558", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 558",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login558", false))));
        rules.add(new Rule("builtin-log-559", Severity.LOW, 10,
            "Built-in log telemetry signal 559",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny559", false))));
        rules.add(new Rule("builtin-http-560", Severity.HIGH, 15,
            "Built-in http telemetry signal 560",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin560", false))));
        rules.add(new Rule("builtin-http-561", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 561",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner561", false))));
        rules.add(new Rule("builtin-dns-562", Severity.LOW, 25,
            "Built-in dns telemetry signal 562",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip562", false))));
        rules.add(new Rule("builtin-tls-563", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 563",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login563", false))));
        rules.add(new Rule("builtin-log-564", Severity.LOW, 35,
            "Built-in log telemetry signal 564",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny564", false))));
        rules.add(new Rule("builtin-http-565", Severity.HIGH, 40,
            "Built-in http telemetry signal 565",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin565", false))));
        rules.add(new Rule("builtin-http-566", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 566",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner566", false))));
        rules.add(new Rule("builtin-dns-567", Severity.LOW, 5,
            "Built-in dns telemetry signal 567",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip567", false))));
        rules.add(new Rule("builtin-tls-568", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 568",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login568", false))));
        rules.add(new Rule("builtin-log-569", Severity.LOW, 15,
            "Built-in log telemetry signal 569",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny569", false))));
        rules.add(new Rule("builtin-http-570", Severity.HIGH, 20,
            "Built-in http telemetry signal 570",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin570", false))));
        rules.add(new Rule("builtin-http-571", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 571",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner571", false))));
        rules.add(new Rule("builtin-dns-572", Severity.LOW, 30,
            "Built-in dns telemetry signal 572",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip572", false))));
        rules.add(new Rule("builtin-tls-573", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 573",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login573", false))));
        rules.add(new Rule("builtin-log-574", Severity.LOW, 40,
            "Built-in log telemetry signal 574",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny574", false))));
        rules.add(new Rule("builtin-http-575", Severity.HIGH, 45,
            "Built-in http telemetry signal 575",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin575", false))));
        rules.add(new Rule("builtin-http-576", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 576",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner576", false))));
        rules.add(new Rule("builtin-dns-577", Severity.LOW, 10,
            "Built-in dns telemetry signal 577",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip577", false))));
        rules.add(new Rule("builtin-tls-578", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 578",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login578", false))));
        rules.add(new Rule("builtin-log-579", Severity.LOW, 20,
            "Built-in log telemetry signal 579",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny579", false))));
        rules.add(new Rule("builtin-http-580", Severity.HIGH, 25,
            "Built-in http telemetry signal 580",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin580", false))));
        rules.add(new Rule("builtin-http-581", Severity.MEDIUM, 30,
            "Built-in http telemetry signal 581",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner581", false))));
        rules.add(new Rule("builtin-dns-582", Severity.LOW, 35,
            "Built-in dns telemetry signal 582",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip582", false))));
        rules.add(new Rule("builtin-tls-583", Severity.MEDIUM, 40,
            "Built-in tls telemetry signal 583",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login583", false))));
        rules.add(new Rule("builtin-log-584", Severity.LOW, 45,
            "Built-in log telemetry signal 584",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny584", false))));
        rules.add(new Rule("builtin-http-585", Severity.HIGH, 5,
            "Built-in http telemetry signal 585",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin585", false))));
        rules.add(new Rule("builtin-http-586", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 586",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner586", false))));
        rules.add(new Rule("builtin-dns-587", Severity.LOW, 15,
            "Built-in dns telemetry signal 587",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip587", false))));
        rules.add(new Rule("builtin-tls-588", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 588",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login588", false))));
        rules.add(new Rule("builtin-log-589", Severity.LOW, 25,
            "Built-in log telemetry signal 589",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny589", false))));
        rules.add(new Rule("builtin-http-590", Severity.HIGH, 30,
            "Built-in http telemetry signal 590",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin590", false))));
        rules.add(new Rule("builtin-http-591", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 591",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner591", false))));
        rules.add(new Rule("builtin-dns-592", Severity.LOW, 40,
            "Built-in dns telemetry signal 592",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip592", false))));
        rules.add(new Rule("builtin-tls-593", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 593",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login593", false))));
        rules.add(new Rule("builtin-log-594", Severity.LOW, 5,
            "Built-in log telemetry signal 594",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny594", false))));
        rules.add(new Rule("builtin-http-595", Severity.HIGH, 10,
            "Built-in http telemetry signal 595",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin595", false))));
        rules.add(new Rule("builtin-http-596", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 596",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner596", false))));
        rules.add(new Rule("builtin-dns-597", Severity.LOW, 20,
            "Built-in dns telemetry signal 597",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip597", false))));
        rules.add(new Rule("builtin-tls-598", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 598",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login598", false))));
        rules.add(new Rule("builtin-log-599", Severity.LOW, 30,
            "Built-in log telemetry signal 599",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny599", false))));
        rules.add(new Rule("builtin-http-600", Severity.HIGH, 35,
            "Built-in http telemetry signal 600",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin600", false))));
        rules.add(new Rule("builtin-http-601", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 601",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner601", false))));
        rules.add(new Rule("builtin-dns-602", Severity.LOW, 45,
            "Built-in dns telemetry signal 602",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip602", false))));
        rules.add(new Rule("builtin-tls-603", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 603",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login603", false))));
        rules.add(new Rule("builtin-log-604", Severity.LOW, 10,
            "Built-in log telemetry signal 604",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny604", false))));
        rules.add(new Rule("builtin-http-605", Severity.HIGH, 15,
            "Built-in http telemetry signal 605",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin605", false))));
        rules.add(new Rule("builtin-http-606", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 606",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner606", false))));
        rules.add(new Rule("builtin-dns-607", Severity.LOW, 25,
            "Built-in dns telemetry signal 607",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip607", false))));
        rules.add(new Rule("builtin-tls-608", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 608",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login608", false))));
        rules.add(new Rule("builtin-log-609", Severity.LOW, 35,
            "Built-in log telemetry signal 609",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny609", false))));
        rules.add(new Rule("builtin-http-610", Severity.HIGH, 40,
            "Built-in http telemetry signal 610",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin610", false))));
        rules.add(new Rule("builtin-http-611", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 611",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner611", false))));
        rules.add(new Rule("builtin-dns-612", Severity.LOW, 5,
            "Built-in dns telemetry signal 612",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip612", false))));
        rules.add(new Rule("builtin-tls-613", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 613",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login613", false))));
        rules.add(new Rule("builtin-log-614", Severity.LOW, 15,
            "Built-in log telemetry signal 614",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny614", false))));
        rules.add(new Rule("builtin-http-615", Severity.HIGH, 20,
            "Built-in http telemetry signal 615",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin615", false))));
        rules.add(new Rule("builtin-http-616", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 616",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner616", false))));
        rules.add(new Rule("builtin-dns-617", Severity.LOW, 30,
            "Built-in dns telemetry signal 617",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip617", false))));
        rules.add(new Rule("builtin-tls-618", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 618",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login618", false))));
        rules.add(new Rule("builtin-log-619", Severity.LOW, 40,
            "Built-in log telemetry signal 619",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny619", false))));
        rules.add(new Rule("builtin-http-620", Severity.HIGH, 45,
            "Built-in http telemetry signal 620",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin620", false))));
        rules.add(new Rule("builtin-http-621", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 621",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner621", false))));
        rules.add(new Rule("builtin-dns-622", Severity.LOW, 10,
            "Built-in dns telemetry signal 622",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip622", false))));
        rules.add(new Rule("builtin-tls-623", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 623",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login623", false))));
        rules.add(new Rule("builtin-log-624", Severity.LOW, 20,
            "Built-in log telemetry signal 624",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny624", false))));
        rules.add(new Rule("builtin-http-625", Severity.HIGH, 25,
            "Built-in http telemetry signal 625",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin625", false))));
        rules.add(new Rule("builtin-http-626", Severity.MEDIUM, 30,
            "Built-in http telemetry signal 626",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner626", false))));
        rules.add(new Rule("builtin-dns-627", Severity.LOW, 35,
            "Built-in dns telemetry signal 627",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip627", false))));
        rules.add(new Rule("builtin-tls-628", Severity.MEDIUM, 40,
            "Built-in tls telemetry signal 628",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login628", false))));
        rules.add(new Rule("builtin-log-629", Severity.LOW, 45,
            "Built-in log telemetry signal 629",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny629", false))));
        rules.add(new Rule("builtin-http-630", Severity.HIGH, 5,
            "Built-in http telemetry signal 630",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin630", false))));
        rules.add(new Rule("builtin-http-631", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 631",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner631", false))));
        rules.add(new Rule("builtin-dns-632", Severity.LOW, 15,
            "Built-in dns telemetry signal 632",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip632", false))));
        rules.add(new Rule("builtin-tls-633", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 633",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login633", false))));
        rules.add(new Rule("builtin-log-634", Severity.LOW, 25,
            "Built-in log telemetry signal 634",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny634", false))));
        rules.add(new Rule("builtin-http-635", Severity.HIGH, 30,
            "Built-in http telemetry signal 635",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin635", false))));
        rules.add(new Rule("builtin-http-636", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 636",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner636", false))));
        rules.add(new Rule("builtin-dns-637", Severity.LOW, 40,
            "Built-in dns telemetry signal 637",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip637", false))));
        rules.add(new Rule("builtin-tls-638", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 638",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login638", false))));
        rules.add(new Rule("builtin-log-639", Severity.LOW, 5,
            "Built-in log telemetry signal 639",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny639", false))));
        rules.add(new Rule("builtin-http-640", Severity.HIGH, 10,
            "Built-in http telemetry signal 640",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin640", false))));
        rules.add(new Rule("builtin-http-641", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 641",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner641", false))));
        rules.add(new Rule("builtin-dns-642", Severity.LOW, 20,
            "Built-in dns telemetry signal 642",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip642", false))));
        rules.add(new Rule("builtin-tls-643", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 643",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login643", false))));
        rules.add(new Rule("builtin-log-644", Severity.LOW, 30,
            "Built-in log telemetry signal 644",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny644", false))));
        rules.add(new Rule("builtin-http-645", Severity.HIGH, 35,
            "Built-in http telemetry signal 645",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin645", false))));
        rules.add(new Rule("builtin-http-646", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 646",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner646", false))));
        rules.add(new Rule("builtin-dns-647", Severity.LOW, 45,
            "Built-in dns telemetry signal 647",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip647", false))));
        rules.add(new Rule("builtin-tls-648", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 648",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login648", false))));
        rules.add(new Rule("builtin-log-649", Severity.LOW, 10,
            "Built-in log telemetry signal 649",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny649", false))));
        rules.add(new Rule("builtin-http-650", Severity.HIGH, 15,
            "Built-in http telemetry signal 650",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin650", false))));
        rules.add(new Rule("builtin-http-651", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 651",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner651", false))));
        rules.add(new Rule("builtin-dns-652", Severity.LOW, 25,
            "Built-in dns telemetry signal 652",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip652", false))));
        rules.add(new Rule("builtin-tls-653", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 653",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login653", false))));
        rules.add(new Rule("builtin-log-654", Severity.LOW, 35,
            "Built-in log telemetry signal 654",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny654", false))));
        rules.add(new Rule("builtin-http-655", Severity.HIGH, 40,
            "Built-in http telemetry signal 655",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin655", false))));
        rules.add(new Rule("builtin-http-656", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 656",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner656", false))));
        rules.add(new Rule("builtin-dns-657", Severity.LOW, 5,
            "Built-in dns telemetry signal 657",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip657", false))));
        rules.add(new Rule("builtin-tls-658", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 658",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login658", false))));
        rules.add(new Rule("builtin-log-659", Severity.LOW, 15,
            "Built-in log telemetry signal 659",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny659", false))));
        rules.add(new Rule("builtin-http-660", Severity.HIGH, 20,
            "Built-in http telemetry signal 660",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin660", false))));
        rules.add(new Rule("builtin-http-661", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 661",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner661", false))));
        rules.add(new Rule("builtin-dns-662", Severity.LOW, 30,
            "Built-in dns telemetry signal 662",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip662", false))));
        rules.add(new Rule("builtin-tls-663", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 663",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login663", false))));
        rules.add(new Rule("builtin-log-664", Severity.LOW, 40,
            "Built-in log telemetry signal 664",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny664", false))));
        rules.add(new Rule("builtin-http-665", Severity.HIGH, 45,
            "Built-in http telemetry signal 665",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin665", false))));
        rules.add(new Rule("builtin-http-666", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 666",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner666", false))));
        rules.add(new Rule("builtin-dns-667", Severity.LOW, 10,
            "Built-in dns telemetry signal 667",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip667", false))));
        rules.add(new Rule("builtin-tls-668", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 668",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login668", false))));
        rules.add(new Rule("builtin-log-669", Severity.LOW, 20,
            "Built-in log telemetry signal 669",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny669", false))));
        rules.add(new Rule("builtin-http-670", Severity.HIGH, 25,
            "Built-in http telemetry signal 670",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin670", false))));
        rules.add(new Rule("builtin-http-671", Severity.MEDIUM, 30,
            "Built-in http telemetry signal 671",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner671", false))));
        rules.add(new Rule("builtin-dns-672", Severity.LOW, 35,
            "Built-in dns telemetry signal 672",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip672", false))));
        rules.add(new Rule("builtin-tls-673", Severity.MEDIUM, 40,
            "Built-in tls telemetry signal 673",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login673", false))));
        rules.add(new Rule("builtin-log-674", Severity.LOW, 45,
            "Built-in log telemetry signal 674",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny674", false))));
        rules.add(new Rule("builtin-http-675", Severity.HIGH, 5,
            "Built-in http telemetry signal 675",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin675", false))));
        rules.add(new Rule("builtin-http-676", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 676",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner676", false))));
        rules.add(new Rule("builtin-dns-677", Severity.LOW, 15,
            "Built-in dns telemetry signal 677",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip677", false))));
        rules.add(new Rule("builtin-tls-678", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 678",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login678", false))));
        rules.add(new Rule("builtin-log-679", Severity.LOW, 25,
            "Built-in log telemetry signal 679",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny679", false))));
        rules.add(new Rule("builtin-http-680", Severity.HIGH, 30,
            "Built-in http telemetry signal 680",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin680", false))));
        rules.add(new Rule("builtin-http-681", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 681",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner681", false))));
        rules.add(new Rule("builtin-dns-682", Severity.LOW, 40,
            "Built-in dns telemetry signal 682",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip682", false))));
        rules.add(new Rule("builtin-tls-683", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 683",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login683", false))));
        rules.add(new Rule("builtin-log-684", Severity.LOW, 5,
            "Built-in log telemetry signal 684",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny684", false))));
        rules.add(new Rule("builtin-http-685", Severity.HIGH, 10,
            "Built-in http telemetry signal 685",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin685", false))));
        rules.add(new Rule("builtin-http-686", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 686",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner686", false))));
        rules.add(new Rule("builtin-dns-687", Severity.LOW, 20,
            "Built-in dns telemetry signal 687",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip687", false))));
        rules.add(new Rule("builtin-tls-688", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 688",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login688", false))));
        rules.add(new Rule("builtin-log-689", Severity.LOW, 30,
            "Built-in log telemetry signal 689",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny689", false))));
        rules.add(new Rule("builtin-http-690", Severity.HIGH, 35,
            "Built-in http telemetry signal 690",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin690", false))));
        rules.add(new Rule("builtin-http-691", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 691",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner691", false))));
        rules.add(new Rule("builtin-dns-692", Severity.LOW, 45,
            "Built-in dns telemetry signal 692",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip692", false))));
        rules.add(new Rule("builtin-tls-693", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 693",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login693", false))));
        rules.add(new Rule("builtin-log-694", Severity.LOW, 10,
            "Built-in log telemetry signal 694",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny694", false))));
        rules.add(new Rule("builtin-http-695", Severity.HIGH, 15,
            "Built-in http telemetry signal 695",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin695", false))));
        rules.add(new Rule("builtin-http-696", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 696",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner696", false))));
        rules.add(new Rule("builtin-dns-697", Severity.LOW, 25,
            "Built-in dns telemetry signal 697",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip697", false))));
        rules.add(new Rule("builtin-tls-698", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 698",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login698", false))));
        rules.add(new Rule("builtin-log-699", Severity.LOW, 35,
            "Built-in log telemetry signal 699",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny699", false))));
        rules.add(new Rule("builtin-http-700", Severity.HIGH, 40,
            "Built-in http telemetry signal 700",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin700", false))));
        rules.add(new Rule("builtin-http-701", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 701",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner701", false))));
        rules.add(new Rule("builtin-dns-702", Severity.LOW, 5,
            "Built-in dns telemetry signal 702",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip702", false))));
        rules.add(new Rule("builtin-tls-703", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 703",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login703", false))));
        rules.add(new Rule("builtin-log-704", Severity.LOW, 15,
            "Built-in log telemetry signal 704",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny704", false))));
        rules.add(new Rule("builtin-http-705", Severity.HIGH, 20,
            "Built-in http telemetry signal 705",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin705", false))));
        rules.add(new Rule("builtin-http-706", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 706",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner706", false))));
        rules.add(new Rule("builtin-dns-707", Severity.LOW, 30,
            "Built-in dns telemetry signal 707",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip707", false))));
        rules.add(new Rule("builtin-tls-708", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 708",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login708", false))));
        rules.add(new Rule("builtin-log-709", Severity.LOW, 40,
            "Built-in log telemetry signal 709",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny709", false))));
        rules.add(new Rule("builtin-http-710", Severity.HIGH, 45,
            "Built-in http telemetry signal 710",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin710", false))));
        rules.add(new Rule("builtin-http-711", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 711",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner711", false))));
        rules.add(new Rule("builtin-dns-712", Severity.LOW, 10,
            "Built-in dns telemetry signal 712",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip712", false))));
        rules.add(new Rule("builtin-tls-713", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 713",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login713", false))));
        rules.add(new Rule("builtin-log-714", Severity.LOW, 20,
            "Built-in log telemetry signal 714",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny714", false))));
        rules.add(new Rule("builtin-http-715", Severity.HIGH, 25,
            "Built-in http telemetry signal 715",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin715", false))));
        rules.add(new Rule("builtin-http-716", Severity.MEDIUM, 30,
            "Built-in http telemetry signal 716",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner716", false))));
        rules.add(new Rule("builtin-dns-717", Severity.LOW, 35,
            "Built-in dns telemetry signal 717",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip717", false))));
        rules.add(new Rule("builtin-tls-718", Severity.MEDIUM, 40,
            "Built-in tls telemetry signal 718",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login718", false))));
        rules.add(new Rule("builtin-log-719", Severity.LOW, 45,
            "Built-in log telemetry signal 719",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny719", false))));
        rules.add(new Rule("builtin-http-720", Severity.HIGH, 5,
            "Built-in http telemetry signal 720",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin720", false))));
        rules.add(new Rule("builtin-http-721", Severity.MEDIUM, 10,
            "Built-in http telemetry signal 721",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner721", false))));
        rules.add(new Rule("builtin-dns-722", Severity.LOW, 15,
            "Built-in dns telemetry signal 722",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip722", false))));
        rules.add(new Rule("builtin-tls-723", Severity.MEDIUM, 20,
            "Built-in tls telemetry signal 723",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login723", false))));
        rules.add(new Rule("builtin-log-724", Severity.LOW, 25,
            "Built-in log telemetry signal 724",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny724", false))));
        rules.add(new Rule("builtin-http-725", Severity.HIGH, 30,
            "Built-in http telemetry signal 725",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin725", false))));
        rules.add(new Rule("builtin-http-726", Severity.MEDIUM, 35,
            "Built-in http telemetry signal 726",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner726", false))));
        rules.add(new Rule("builtin-dns-727", Severity.LOW, 40,
            "Built-in dns telemetry signal 727",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip727", false))));
        rules.add(new Rule("builtin-tls-728", Severity.MEDIUM, 45,
            "Built-in tls telemetry signal 728",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login728", false))));
        rules.add(new Rule("builtin-log-729", Severity.LOW, 5,
            "Built-in log telemetry signal 729",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny729", false))));
        rules.add(new Rule("builtin-http-730", Severity.HIGH, 10,
            "Built-in http telemetry signal 730",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin730", false))));
        rules.add(new Rule("builtin-http-731", Severity.MEDIUM, 15,
            "Built-in http telemetry signal 731",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner731", false))));
        rules.add(new Rule("builtin-dns-732", Severity.LOW, 20,
            "Built-in dns telemetry signal 732",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip732", false))));
        rules.add(new Rule("builtin-tls-733", Severity.MEDIUM, 25,
            "Built-in tls telemetry signal 733",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login733", false))));
        rules.add(new Rule("builtin-log-734", Severity.LOW, 30,
            "Built-in log telemetry signal 734",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny734", false))));
        rules.add(new Rule("builtin-http-735", Severity.HIGH, 35,
            "Built-in http telemetry signal 735",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin735", false))));
        rules.add(new Rule("builtin-http-736", Severity.MEDIUM, 40,
            "Built-in http telemetry signal 736",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner736", false))));
        rules.add(new Rule("builtin-dns-737", Severity.LOW, 45,
            "Built-in dns telemetry signal 737",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip737", false))));
        rules.add(new Rule("builtin-tls-738", Severity.MEDIUM, 5,
            "Built-in tls telemetry signal 738",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login738", false))));
        rules.add(new Rule("builtin-log-739", Severity.LOW, 10,
            "Built-in log telemetry signal 739",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny739", false))));
        rules.add(new Rule("builtin-http-740", Severity.HIGH, 15,
            "Built-in http telemetry signal 740",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin740", false))));
        rules.add(new Rule("builtin-http-741", Severity.MEDIUM, 20,
            "Built-in http telemetry signal 741",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner741", false))));
        rules.add(new Rule("builtin-dns-742", Severity.LOW, 25,
            "Built-in dns telemetry signal 742",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip742", false))));
        rules.add(new Rule("builtin-tls-743", Severity.MEDIUM, 30,
            "Built-in tls telemetry signal 743",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login743", false))));
        rules.add(new Rule("builtin-log-744", Severity.LOW, 35,
            "Built-in log telemetry signal 744",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny744", false))));
        rules.add(new Rule("builtin-http-745", Severity.HIGH, 40,
            "Built-in http telemetry signal 745",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin745", false))));
        rules.add(new Rule("builtin-http-746", Severity.MEDIUM, 45,
            "Built-in http telemetry signal 746",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner746", false))));
        rules.add(new Rule("builtin-dns-747", Severity.LOW, 5,
            "Built-in dns telemetry signal 747",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip747", false))));
        rules.add(new Rule("builtin-tls-748", Severity.MEDIUM, 10,
            "Built-in tls telemetry signal 748",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login748", false))));
        rules.add(new Rule("builtin-log-749", Severity.LOW, 15,
            "Built-in log telemetry signal 749",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny749", false))));
        rules.add(new Rule("builtin-http-750", Severity.HIGH, 20,
            "Built-in http telemetry signal 750",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin750", false))));
        rules.add(new Rule("builtin-http-751", Severity.MEDIUM, 25,
            "Built-in http telemetry signal 751",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner751", false))));
        rules.add(new Rule("builtin-dns-752", Severity.LOW, 30,
            "Built-in dns telemetry signal 752",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip752", false))));
        rules.add(new Rule("builtin-tls-753", Severity.MEDIUM, 35,
            "Built-in tls telemetry signal 753",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login753", false))));
        rules.add(new Rule("builtin-log-754", Severity.LOW, 40,
            "Built-in log telemetry signal 754",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny754", false))));
        rules.add(new Rule("builtin-http-755", Severity.HIGH, 45,
            "Built-in http telemetry signal 755",
            Arrays.asList("reconnaissance", "built-in"),
            Arrays.asList(new Condition("http.path", "contains", "/admin755", false))));
        rules.add(new Rule("builtin-http-756", Severity.MEDIUM, 5,
            "Built-in http telemetry signal 756",
            Arrays.asList("automation", "built-in"),
            Arrays.asList(new Condition("http.header.user-agent", "contains", "scanner756", false))));
        rules.add(new Rule("builtin-dns-757", Severity.LOW, 10,
            "Built-in dns telemetry signal 757",
            Arrays.asList("dns", "built-in"),
            Arrays.asList(new Condition("dns.question.0.name", "suffix", ".zip757", false))));
        rules.add(new Rule("builtin-tls-758", Severity.MEDIUM, 15,
            "Built-in tls telemetry signal 758",
            Arrays.asList("identity", "built-in"),
            Arrays.asList(new Condition("tls.sni", "contains", "login758", false))));
        rules.add(new Rule("builtin-log-759", Severity.LOW, 20,
            "Built-in log telemetry signal 759",
            Arrays.asList("access", "built-in"),
            Arrays.asList(new Condition("log.action", "equals", "deny759", false))));
        return new PolicyBundle(rules);
    }
}