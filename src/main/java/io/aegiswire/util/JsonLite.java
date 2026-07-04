package io.aegiswire.util;
import java.util.*;
public final class JsonLite { private JsonLite() {}
    public static String quote(String s) { StringBuilder b=new StringBuilder("\""); if(s!=null) for(int i=0;i<s.length();i++){ char c=s.charAt(i); if(c=='\\'||c=='\"') b.append('\\').append(c); else if(c=='\n') b.append("\\n"); else if(c=='\r') b.append("\\r"); else if(c=='\t') b.append("\\t"); else b.append(c);} return b.append('\"').toString(); }
    public static String object(Map<String,String> m) { StringBuilder b=new StringBuilder("{"); boolean first=true; for(Map.Entry<String,String> e:m.entrySet()){ if(!first)b.append(','); first=false; b.append(quote(e.getKey())).append(':').append(quote(e.getValue())); } return b.append('}').toString(); }
    public static Map<String,String> flatObject(String s) { Map<String,String> out=new LinkedHashMap<String,String>(); String t=s.trim(); if(t.startsWith("{")&&t.endsWith("}")) t=t.substring(1,t.length()-1); for(String p:t.split(",")){ int i=p.indexOf(':'); if(i>0) out.put(strip(p.substring(0,i)), strip(p.substring(i+1))); } return out; }
    private static String strip(String s){ s=s.trim(); if(s.length()>1&&s.startsWith("\"")&&s.endsWith("\"")) return s.substring(1,s.length()-1); return s; }
}
