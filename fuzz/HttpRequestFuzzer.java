import io.aegiswire.core.ParseException;
public class HttpRequestFuzzer {
    public static void fuzzerTestOneInput(byte[] data) throws Exception {
        try {
            new io.aegiswire.http.HttpRequestParser().parse(data);
        } catch (ParseException | IllegalArgumentException expected) {
        }
    }
}
