package io.aegiswire.http;
import java.util.*;
public class HeaderMap {
    private final Map<String,List<String>> values = new LinkedHashMap<String,List<String>>();
    public void add(String name, String value) { String key=name.trim().toLowerCase(Locale.ROOT); List<String> list=values.get(key); if(list==null){list=new ArrayList<String>(); values.put(key,list);} list.add(value.trim()); }
    public String first(String name) { List<String> v=values.get(name.toLowerCase(Locale.ROOT)); return v==null||v.isEmpty()?"":v.get(0); }
    public List<String> all(String name) { List<String> v=values.get(name.toLowerCase(Locale.ROOT)); return v==null?Collections.<String>emptyList():Collections.unmodifiableList(v); }
    public Set<String> names() { return Collections.unmodifiableSet(values.keySet()); } public int size() { int n=0; for(List<String> v:values.values()) n+=v.size(); return n; }
}
