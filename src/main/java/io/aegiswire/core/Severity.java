package io.aegiswire.core;
public enum Severity {
    INFO(1), LOW(2), MEDIUM(4), HIGH(7), CRITICAL(10);
    private final int weight;
    Severity(int weight) { this.weight = weight; }
    public int weight() { return weight; }
    public static Severity parse(String value) {
        if (value == null) return INFO;
        String v = value.trim().toUpperCase();
        for (Severity s : values()) if (s.name().equals(v)) return s;
        return INFO;
    }
}
