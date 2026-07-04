package io.aegiswire.core;
import io.aegiswire.http.*; import io.aegiswire.dns.*; import io.aegiswire.tls.*; import io.aegiswire.log.*; import java.util.*;
public class ScanContext {
    private final Map<String,String> fields = new LinkedHashMap<String,String>(); private final List<Finding> findings = new ArrayList<Finding>();
    public static ScanContext forHttp(HttpRequest r) { ScanContext c = new ScanContext(); c.put("event.kind","http"); c.put("http.method",r.method()); c.put("http.path",r.path()); c.put("http.version",r.version()); for (String n : r.headers().names()) c.put("http.header."+n.toLowerCase(Locale.ROOT), r.headers().first(n)); for (Map.Entry<String,String> e : r.query().entrySet()) c.put("http.query."+e.getKey().toLowerCase(Locale.ROOT), e.getValue()); return c; }
    public static ScanContext forDns(DnsMessage m) { ScanContext c = new ScanContext(); c.put("event.kind","dns"); c.put("dns.id",Integer.toString(m.id())); c.put("dns.opcode",Integer.toString(m.opcode())); int i=0; for (DnsQuestion q : m.questions()) { c.put("dns.question."+i+".name",q.name()); c.put("dns.question."+i+".type",Integer.toString(q.type())); i++; } return c; }
    public static ScanContext forTls(TlsClientHello h) { ScanContext c = new ScanContext(); c.put("event.kind","tls"); c.put("tls.version",h.version()); c.put("tls.sni",h.serverName()); c.put("tls.alpn",h.alpnCsv()); c.put("tls.cipher.count",Integer.toString(h.cipherSuites().size())); return c; }
    public static ScanContext forLog(LogEvent e) { ScanContext c = new ScanContext(); c.put("event.kind","log"); for (Map.Entry<String,String> x : e.fields().entrySet()) c.put("log."+x.getKey().toLowerCase(Locale.ROOT), x.getValue()); return c; }
    public void put(String k, String v) { if (k != null && v != null) fields.put(k, v); } public String get(String k) { return fields.get(k); }
    public boolean has(String k) { return fields.containsKey(k); } public Set<String> keys() { return Collections.unmodifiableSet(fields.keySet()); }
    public Map<String,String> fields() { return Collections.unmodifiableMap(fields); } public void add(Finding f) { findings.add(f); }
    public List<Finding> findings() { return Collections.unmodifiableList(findings); }
}
