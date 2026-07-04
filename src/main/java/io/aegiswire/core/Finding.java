package io.aegiswire.core;
import java.util.*;
public class Finding {
    private final String id; private final Severity severity; private final String message; private final Map<String,String> evidence;
    public Finding(String id, Severity severity, String message) { this(id, severity, message, new LinkedHashMap<String,String>()); }
    public Finding(String id, Severity severity, String message, Map<String,String> evidence) {
        this.id = id; this.severity = severity; this.message = message; this.evidence = new LinkedHashMap<String,String>(evidence);
    }
    public String id() { return id; } public Severity severity() { return severity; } public String message() { return message; }
    public Map<String,String> evidence() { return Collections.unmodifiableMap(evidence); }
    public Finding with(String k, String v) { Map<String,String> e = new LinkedHashMap<String,String>(evidence); e.put(k, v); return new Finding(id, severity, message, e); }
}
