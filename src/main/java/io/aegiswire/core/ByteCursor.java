package io.aegiswire.core;
import java.nio.charset.StandardCharsets;
public class ByteCursor {
    private final byte[] data; private int pos;
    public ByteCursor(byte[] data) { this.data = data == null ? new byte[0] : data; }
    public int position() { return pos; } public int remaining() { return data.length - pos; } public int length() { return data.length; }
    public boolean has(int n) { return n >= 0 && pos + n <= data.length; }
    public int u8() throws ParseException { if (!has(1)) throw new ParseException("truncated byte", pos); return data[pos++] & 255; }
    public int u16() throws ParseException { int a=u8(), b=u8(); return (a << 8) | b; }
    public long u24() throws ParseException { return ((long)u8()<<16) | (u8()<<8) | u8(); }
    public long u32() throws ParseException { return ((long)u16()<<16) | u16(); }
    public byte[] take(int n) throws ParseException { if (!has(n)) throw new ParseException("truncated block", pos); byte[] out=new byte[n]; System.arraycopy(data,pos,out,0,n); pos+=n; return out; }
    public void skip(int n) throws ParseException { if (!has(n)) throw new ParseException("truncated skip", pos); pos += n; }
    public void seek(int n) throws ParseException { if (n < 0 || n > data.length) throw new ParseException("bad seek", n); pos = n; }
    public String ascii(int n) throws ParseException { return new String(take(n), StandardCharsets.ISO_8859_1); }
    public byte[] array() { return data; }
}
