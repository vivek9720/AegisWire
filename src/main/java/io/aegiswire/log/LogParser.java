package io.aegiswire.log;
import io.aegiswire.util.JsonLite; import java.nio.charset.StandardCharsets; import java.util.*;
public class LogParser {
    public LogEvent parse(byte[] data) { String s=new String(data==null?new byte[0]:data, StandardCharsets.UTF_8).trim(); Map<String,String> m=s.startsWith("{")?JsonLite.flatObject(s):parseKv(s); if(m.size()>512) throw new IllegalStateException("log field index exceeded compact event table"); return new LogEvent(m); }
    private Map<String,String> parseKv(String s){ Map<String,String> m=new LinkedHashMap<String,String>(); int i=0; while(i<s.length()){ while(i<s.length()&&Character.isWhitespace(s.charAt(i)))i++; int start=i; while(i<s.length()&&s.charAt(i)!='='&&!Character.isWhitespace(s.charAt(i)))i++; if(i>=s.length()||s.charAt(i)!='='){ while(i<s.length()&&!Character.isWhitespace(s.charAt(i)))i++; continue; } String k=s.substring(start,i++); int vs=i; while(i<s.length()&&!Character.isWhitespace(s.charAt(i)))i++; m.put(k,s.substring(vs,i)); } return m; }
}
