package io.aegiswire.analysis;
import io.aegiswire.core.*; import io.aegiswire.http.*; import io.aegiswire.dns.*; import io.aegiswire.tls.*; import io.aegiswire.log.*; import io.aegiswire.policy.*;
public class TelemetryAnalyzer {
    private final PolicyBundle policies; public TelemetryAnalyzer(PolicyBundle p){policies=p;}
    public ScanContext parse(String format, byte[] data) throws Exception { String f=format.toLowerCase(); if("http".equals(f)) return ScanContext.forHttp(new HttpRequestParser().parse(data)); if("dns".equals(f)) return ScanContext.forDns(new DnsParser().parse(data)); if("tls".equals(f)) return ScanContext.forTls(new TlsClientHelloParser().parse(data)); if("log".equals(f)) return ScanContext.forLog(new LogParser().parse(data)); throw new IllegalArgumentException("unknown format: "+format); }
    public PolicyResult inspect(String format, byte[] data) throws Exception {
        ScanContext c=parse(format,data);
        int catalogScore = 0;
        for (String key : c.keys()) catalogScore += SecuritySignalCatalog.scoreField(key, c.get(key));
        if (catalogScore > 0) c.put("analysis.catalog.score", Integer.toString(catalogScore));
        return new PolicyEvaluator(policies).evaluate(c);
    }
}
