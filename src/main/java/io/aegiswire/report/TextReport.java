package io.aegiswire.report;
import io.aegiswire.policy.*; import io.aegiswire.core.*;
public class TextReport { public String render(PolicyResult r){ StringBuilder b=new StringBuilder(); b.append("score: ").append(r.score()).append('\n'); b.append("severity: ").append(r.maxSeverity()).append('\n'); for(Finding f:r.findings()) b.append(f.severity()).append(' ').append(f.id()).append(" - ").append(f.message()).append('\n'); return b.toString(); } }
