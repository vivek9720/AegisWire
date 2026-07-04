package io.aegiswire.http;
import java.util.*;
public class HttpRequest {
    private final String method,path,version; private final HeaderMap headers; private final byte[] body; private final Map<String,String> query;
    public HttpRequest(String method,String path,String version,HeaderMap headers,byte[] body,Map<String,String> query){this.method=method;this.path=path;this.version=version;this.headers=headers;this.body=body;this.query=new LinkedHashMap<String,String>(query);}
    public String method(){return method;} public String path(){return path;} public String version(){return version;} public HeaderMap headers(){return headers;} public byte[] body(){return body;} public Map<String,String> query(){return Collections.unmodifiableMap(query);}
}
