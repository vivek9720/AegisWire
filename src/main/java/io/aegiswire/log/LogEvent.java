package io.aegiswire.log;
import java.util.*;
public class LogEvent { private final Map<String,String> fields; public LogEvent(Map<String,String> f){fields=new LinkedHashMap<String,String>(f);} public Map<String,String> fields(){return Collections.unmodifiableMap(fields);} public String get(String k){return fields.get(k);} }
