use std::{collections::HashMap, error::Error};

use super::proto::DnsLabel;



#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[allow(dead_code)]
pub enum RuleTrieKey {
    Label(DnsLabel),
    Wildcard
}
#[allow(dead_code)]
pub struct RuleTrieKeyString {
    keys: Vec<RuleTrieKey>,
}

impl<'a> From<String> for RuleTrieKeyString {
    fn from(string: String) -> Self {
        let keys = string.split('.').map(|x| (false, x)).map(|(stop_processing_wildcards, x)| {
            
            let mut next_stop_processing_wildcards = stop_processing_wildcards;
            let new_label = if x == "*" && !stop_processing_wildcards {
                RuleTrieKey::Wildcard
            } else {
                next_stop_processing_wildcards = true;
                RuleTrieKey::Label(DnsLabel::from(x.to_string()))
            };
            (next_stop_processing_wildcards, new_label)
        }).map(|(_b, x)| x).collect::<Vec<RuleTrieKey>>();
        RuleTrieKeyString { keys }
    }
}

impl RuleTrieKeyString {
    #[allow(dead_code)]
    pub fn left_pop_clone(&self) -> Option<(RuleTrieKey, RuleTrieKeyString)> {
        if self.keys.len() == 0 {
            return None;
        }
        let mut keys = self.keys.clone();
        let key = keys.remove(0);
        Some((key, RuleTrieKeyString { keys }))
    }
}



#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum RuleTrieNode<T> {
    Continue(RuleTrie<T>),
    Elem(T),
    None,
}

#[allow(dead_code)]
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

    pub fn extract_continue(&self) -> Option<&RuleTrie<T>> {
        match self {
            RuleTrieNode::Continue(trie) => Some(trie),
            RuleTrieNode::Elem(_) => None,
            RuleTrieNode::None => None,
        }
    }

    pub fn extract_elem(&self) -> Option<&T> {
        match self {
            RuleTrieNode::Continue(_) => None,
            RuleTrieNode::Elem(elem) => Some(elem),
            RuleTrieNode::None => None,
        }
    }
}



#[derive(Debug, PartialEq, Eq)]
pub struct RuleTrie<T>(HashMap<RuleTrieKey, RuleTrieNode<T>>);

impl<T> RuleTrie<T> where T: std::fmt::Debug {
    pub fn new() -> Self {
        RuleTrie(HashMap::new())
    }
    #[allow(dead_code)]
    pub fn insert(&mut self, key: RuleTrieKeyString, value: T) -> Result<(), Box<dyn Error>> {
        let keyfrag = key.left_pop_clone();
        match keyfrag {
            Some((key_left_frag, keyfrag)) => {
                let node = self.0.entry(key_left_frag);
                match node {
                    std::collections::hash_map::Entry::Occupied(mut node) => {
                        let node = node.get_mut();
                        match node {
                            RuleTrieNode::Continue(trie) => trie.insert(keyfrag, value),
                            RuleTrieNode::Elem(_) => {
                                return Err("Cannot insert into trie, key already exists".into())
                            }
                            RuleTrieNode::None => {
                                return Err("Cannot insert into trie, key already exists".into())
                            }
                        }
                    }
                    std::collections::hash_map::Entry::Vacant(node) => {
                        match keyfrag.keys.len() {
                            0 => {
                                node.insert(RuleTrieNode::Elem(value));
                                Ok(())
                            }
                            _ => {
                                node.insert(RuleTrieNode::Continue(RuleTrie::new()));
                                self.insert(key, value)
                            }
                        }
                    }
                }

            }
            None => {
                return Ok(())
            }
        }
    }

    #[allow(dead_code)]
    pub fn get(&self, key: RuleTrieKeyString) -> Option<&T> {
        let keyfrag = key.left_pop_clone();
        match keyfrag {
            Some((key_left_frag, keyfrag)) => {
                println!("key_left_frag: {:?}", key_left_frag);
                let node = if self.0.contains_key(&key_left_frag) {
                    self.0.get(&key_left_frag)
                } else {
                    match self.0.get(&RuleTrieKey::Wildcard) {
                        Some(node) => Some(node),
                        None => self.0.get(&key_left_frag),
                    }
                };
                println!("node: {:?}", node);
                match node {
                    Some(node) => {
                        match node {
                            RuleTrieNode::Continue(trie) => trie.get(keyfrag),
                            RuleTrieNode::Elem(elem) => Some(elem),
                            RuleTrieNode::None => None,
                        }
                        
                    }
                    None => None,
                }
            }
            None => None,
        }
    }
}


mod test {
    #[allow(unused_imports)]
    use super::*;
    
    #[test]
    fn test_rule_trie() {
        //the keys are left to right, DNS names are RTL
        let mut trie = RuleTrie::new();
        trie.insert("foo.bar.baz".to_string().into(), 1).unwrap();
        trie.insert("foo.bar.qux".to_string().into(), 2).unwrap();
        trie.insert("foo.bar".to_string().into(), 3).unwrap();
        trie.insert("*.foo.xyz".to_string().into(), 69).unwrap();
        trie.insert("*.*.foo.xyz".to_string().into(), 420).unwrap();
        trie.insert("*.zxcv.foo.xyz".to_string().into(), 1337).unwrap();
        trie.insert("*.*.xyz".to_string().into(), 80000).unwrap();
        assert_eq!(trie.get("foo.bar.baz".to_string().into()), Some(&1));
        assert_eq!(trie.get("asdf_wildcard_test.foo.xyz".to_string().into()), Some(&69));
        assert_eq!(trie.get("asdf_wildcard_test.asdf.foo.xyz".to_string().into()), Some(&420));
        assert_eq!(trie.get("asdf_wildcard_test.zxcv.foo.xyz".to_string().into()), Some(&1337));
    }
}