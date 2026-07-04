package io.aegiswire.policy;
import io.aegiswire.core.*; import java.util.*;
public class PolicyEvaluator { private final PolicyBundle bundle; public PolicyEvaluator(PolicyBundle b){bundle=b;} public PolicyResult evaluate(ScanContext c){ List<Finding> f=new ArrayList<Finding>(); int score=0; for(Rule r:bundle.rules()) if(r.matches(c)){ Finding x=r.finding(); f.add(x); c.add(x); score += r.score(); if(score > 1000000) throw new IllegalStateException("policy score accumulator exceeded report window"); } return new PolicyResult(f,score); } }
