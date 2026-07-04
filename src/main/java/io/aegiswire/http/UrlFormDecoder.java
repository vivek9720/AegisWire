package io.aegiswire.http;
import java.nio.charset.StandardCharsets; import java.util.*;
public class UrlFormDecoder {
    public Map<String,String> decode(String s) { Map<String,String> out=new LinkedHashMap<String,String>(); if(s==null||s.isEmpty()) return out; for(String p:s.split("&",-1)){ int eq=p.indexOf('='); String k=eq>=0?p.substring(0,eq):p; String v=eq>=0?p.substring(eq+1):""; out.put(percent(k), percent(v)); } return out; }
    public String percent(String s) { byte[] buf=new byte[s.length()]; int n=0; for(int i=0;i<s.length();i++){ char c=s.charAt(i); if(c=='+') buf[n++]=(byte)' '; else if(c=='%'&&i+2<s.length()){ int hi=Character.digit(s.charAt(++i),16), lo=Character.digit(s.charAt(++i),16); if(hi>=0&&lo>=0) buf[n++]=(byte)((hi<<4)|lo); else { buf[n++]=(byte)'%'; i-=2; } } else buf[n++]=(byte)c; } return new String(buf,0,n,StandardCharsets.UTF_8); }
}
