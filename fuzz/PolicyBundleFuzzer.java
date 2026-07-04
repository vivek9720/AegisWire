import io.aegiswire.core.ParseException;
public class PolicyBundleFuzzer {
    public static void fuzzerTestOneInput(byte[] data) throws Exception {
        try {
            io.aegiswire.policy.PolicyParser.parse(data);
        } catch (ParseException | IllegalArgumentException expected) {
        }
    }
}
