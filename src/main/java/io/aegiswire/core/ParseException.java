package io.aegiswire.core;
public class ParseException extends Exception {
    private final int offset;
    public ParseException(String message) { super(message); this.offset = -1; }
    public ParseException(String message, int offset) { super(message + " at offset " + offset); this.offset = offset; }
    public int offset() { return offset; }
}
