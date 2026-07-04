import io.aegiswire.core.ParseException;
public class TlsClientHelloFuzzer {
    public static void fuzzerTestOneInput(byte[] data) throws Exception {
        try {
            new io.aegiswire.tls.TlsClientHelloParser().parse(data);
        } catch (ParseException | IllegalArgumentException expected) {
        }
    }
}
