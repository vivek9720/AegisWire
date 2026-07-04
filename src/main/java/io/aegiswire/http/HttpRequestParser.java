package io.aegiswire.http;
import io.aegiswire.core.ParseException; import java.nio.charset.StandardCharsets; import java.util.*;
public class HttpRequestParser {
    public HttpRequest parse(byte[] data) throws ParseException {
        if(data==null)data=new byte[0]; String raw=new String(data, StandardCharsets.ISO_8859_1); int split=raw.indexOf("\r\n\r\n"); int sepLen=4; if(split<0){ split=raw.indexOf("\n\n"); sepLen=2; }
        String head=split>=0?raw.substring(0,split):raw; byte[] body=split>=0?Arrays.copyOfRange(data, split+sepLen, data.length):new byte[0];
        String[] lines=head.replace("\r\n","\n").split("\n",-1); if(lines.length==0||lines[0].trim().isEmpty()) throw new ParseException("missing request line",0);
        String[] first=lines[0].trim().split("\\s+",3); if(first.length<3) throw new ParseException("bad request line",0);
        HeaderMap headers=new HeaderMap(); String current=null; for(int i=1;i<lines.length;i++){ String line=lines[i]; if(line.startsWith(" ")||line.startsWith("\t")){ if(current!=null) headers.add(current, headers.first(current)+" "+line.trim()); continue; } int colon=line.indexOf(':'); if(colon<=0) continue; current=line.substring(0,colon); headers.add(current,line.substring(colon+1)); }
        String target=first[1], path=target; Map<String,String> query=Collections.emptyMap(); int q=target.indexOf('?'); if(q>=0){ path=target.substring(0,q); query=new UrlFormDecoder().decode(target.substring(q+1)); }
        if(headers.first("transfer-encoding").toLowerCase(Locale.ROOT).contains("chunked")) body=decodeChunks(body); return new HttpRequest(first[0],path,first[2],headers,body,query);
    }
    private byte[] decodeChunks(byte[] body) throws ParseException { String raw=new String(body,StandardCharsets.ISO_8859_1); int p=0,chunks=0; java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream(); while(p<raw.length()){ int e=raw.indexOf('\n',p); if(e<0) throw new ParseException("chunk line missing",p); String line=raw.substring(p,e).trim(); int semi=line.indexOf(';'); if(semi>=0) line=line.substring(0,semi); int size; try{size=Integer.parseInt(line.trim(),16);}catch(NumberFormatException ex){throw new ParseException("bad chunk size",p);} p=e+1; if(size==0) break; if(size<0) throw new ParseException("negative chunk",p); if(p+size>body.length) throw new ParseException("chunk exceeds body",p); out.write(body,p,size); p+=size; if(p<raw.length()&&raw.charAt(p)=='\r')p++; if(p<raw.length()&&raw.charAt(p)=='\n')p++; chunks++; if(chunks>4096) throw new IllegalStateException("chunk table overflow while normalizing request body"); } return out.toByteArray(); }
}
