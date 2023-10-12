use std::collections::HashMap;

use super::proto::DnsLabel;



#[derive(Debug, PartialEq, Eq, Hash)]
enum RuleTrieKey {
    Label(DnsLabel),
    Wildcard
}

struct RuleTrieKeyString {
    keys: Vec<RuleTrieKey>,
}

impl<'a> From<String> for RuleTrieKeyString {
    fn from(string: String) -> Self {
        let keys = string.split('.').map(|x| RuleTrieKey::Label(DnsLabel::from(x.to_string()))).collect();
        RuleTrieKeyString { keys }
    }
}



#[derive(Debug, PartialEq, Eq)]
enum RuleTrieNode<T> {
    Continue(RuleTrie<T>),
    Elem(T),
    None,
}

impl<'a, T> RuleTrieNode<T> {
    pub fn is_continue(&self) -> bool {
        match self {
            RuleTrieNode::Continue(_) => true,
            RuleTrieNode::Elem(_) => false,
            RuleTrieNode::None => false,
        }
    }
    pub fn is_elem(&self) -> bool {
        match self {
            RuleTrieNode::Continue(_) => false,
            RuleTrieNode::Elem(_) => true,
            RuleTrieNode::None => false,
        }
    }
    pub fn is_none(&self) -> bool {
        match self {
            RuleTrieNode::Continue(_) => false,
            RuleTrieNode::Elem(_) => false,
            RuleTrieNode::None => true,
        }
    }
}



#[derive(Debug, PartialEq, Eq)]
pub struct RuleTrie<T>(HashMap<RuleTrieKey, RuleTrieNode<T>>);

impl<'a, T> RuleTrie<T> {
    
}

