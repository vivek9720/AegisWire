package io.aegiswire.http;
import java.util.*;
public class CookieParser {
    public Map<String,String> parse(String header) { Map<String,String> out=new LinkedHashMap<String,String>(); if(header==null)return out; for(String part:header.split(";")){ String p=part.trim(); if(p.isEmpty())continue; int eq=p.indexOf('='); if(eq>0) out.put(p.substring(0,eq).trim(), p.substring(eq+1).trim()); else out.put(p,""); } return out; }
    public boolean hasSessionLikeCookie(String header){ for(String k:parse(header).keySet()){ String x=k.toLowerCase(Locale.ROOT); if(x.contains("session")||x.contains("token")||x.equals("sid")) return true; } return false; }
}
