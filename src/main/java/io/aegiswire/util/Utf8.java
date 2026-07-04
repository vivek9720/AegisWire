package io.aegiswire.util;
import java.nio.charset.*;
public final class Utf8 { private Utf8(){} public static String loose(byte[] data){return new String(data==null?new byte[0]:data,StandardCharsets.UTF_8);} public static byte[] bytes(String s){return (s==null?"":s).getBytes(StandardCharsets.UTF_8);} }
