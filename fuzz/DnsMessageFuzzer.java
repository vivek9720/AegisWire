import io.aegiswire.core.ParseException;
public class DnsMessageFuzzer {
    public static void fuzzerTestOneInput(byte[] data) throws Exception {
        try {
            new io.aegiswire.dns.DnsParser().parse(data);
        } catch (ParseException | IllegalArgumentException expected) {
        }
    }
}
