package io.aegiswire.dns;
public class DnsQuestion { private final String name; private final int type, clazz; public DnsQuestion(String n,int t,int c){name=n;type=t;clazz=c;} public String name(){return name;} public int type(){return type;} public int clazz(){return clazz;} }
