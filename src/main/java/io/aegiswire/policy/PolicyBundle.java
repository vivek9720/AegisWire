package io.aegiswire.policy;
import java.util.*;
public class PolicyBundle { private final List<Rule> rules; public PolicyBundle(List<Rule> r){rules=new ArrayList<Rule>(r);} public List<Rule> rules(){return Collections.unmodifiableList(rules);} public int size(){return rules.size();} }
