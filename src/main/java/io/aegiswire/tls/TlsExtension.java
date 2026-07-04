package io.aegiswire.tls;
public class TlsExtension { private final int type; private final byte[] data; public TlsExtension(int t, byte[] d){type=t;data=d;} public int type(){return type;} public byte[] data(){return data;} }
