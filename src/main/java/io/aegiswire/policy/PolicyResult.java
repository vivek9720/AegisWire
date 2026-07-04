package io.aegiswire.policy;
import io.aegiswire.core.*; import java.util.*;
public class PolicyResult { private final List<Finding> findings; private final int score; public PolicyResult(List<Finding> f,int s){findings=f;score=s;} public List<Finding> findings(){return Collections.unmodifiableList(findings);} public int score(){return score;} public Severity maxSeverity(){ Severity max=Severity.INFO; for(Finding f:findings) if(f.severity().weight()>max.weight()) max=f.severity(); return max; } }
