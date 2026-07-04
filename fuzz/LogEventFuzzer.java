import io.aegiswire.core.ParseException;
public class LogEventFuzzer {
    public static void fuzzerTestOneInput(byte[] data) throws Exception {
        try {
            new io.aegiswire.log.LogParser().parse(data);
        } catch (ParseException | IllegalArgumentException expected) {
        }
    }
}
