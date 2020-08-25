// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use log::debug;

#[derive(Debug)]
struct Node<T> {
    v: T,
    left: NodePtr<T>,
    right: NodePtr<T>,
}

type NodePtr<T> = Option<Box<Node<T>>>;

#[derive(Debug)]
pub struct BinarySearchTree<T> {
    root: NodePtr<T>,
}

impl<T> Node<T> {
    fn new(v: T) -> NodePtr<T> {
        Some(Box::new(Self {
            v,
            left: None,
            right: None,
        }))
    }
}

impl<T> BinarySearchTree<T> {
    pub fn new() -> Self {
        Self { root: None }
    }

    fn find_slot(&mut self, v: &T) -> &mut NodePtr<T>
    where
        T: Ord,
    {
        let mut current = &mut self.root;
        while current.is_some() {
            if &current.as_ref().unwrap().v == v {
                break;
            }
            use std::cmp::Ordering;
            let inner = current.as_mut().unwrap();
            match v.cmp(&inner.v) {
                Ordering::Less => current = &mut inner.left,
                Ordering::Greater => current = &mut inner.right,
                Ordering::Equal => unreachable!(),
            }
        }
        current
    }

    pub fn insert(&mut self, v: T)
    where
        T: Ord,
    {
        let slot = self.find_slot(&v);
        if slot.is_none() {
            *slot = Node::new(v);
        }
    }

    pub fn contains(&self, v: &T) -> bool
    where
        T: Ord + std::fmt::Debug,
    {
        let mut current = &self.root;
        while let Some(inner) = current {
            debug!("Stepping through {:?}", inner.v);
            use std::cmp::Ordering;
            match v.cmp(&inner.v) {
                Ordering::Less => current = &inner.left,
                Ordering::Greater => current = &inner.right,
                Ordering::Equal => return true,
            }
        }
        false
    }
}

impl<T: Ord> std::iter::FromIterator<T> for BinarySearchTree<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut tree = BinarySearchTree::default();
        tree.extend(iter);
        tree
    }
}

impl<T> Default for BinarySearchTree<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Ord> std::iter::Extend<T> for BinarySearchTree<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for i in iter {
            self.insert(i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_contains() {
        let mut x = BinarySearchTree::new();
        x.insert(5);
        x.insert(6);
        assert!(x.contains(&5));
        assert!(x.contains(&6));
        assert!(!x.contains(&7));
    }

    #[test]
    fn test_structure() {
        let mut x = BinarySearchTree::new();
        x.insert(10);
        x.insert(15);
        x.insert(17);
        x.insert(13);
        x.insert(5);

        assert!(x.root.as_ref().unwrap().v == 10);
        assert!(x.root.as_ref().unwrap().left.as_ref().unwrap().v == 5);
        assert!(x.root.as_ref().unwrap().right.as_ref().unwrap().v == 15);
        assert!(
            x.root
                .as_ref()
                .unwrap()
                .right
                .as_ref()
                .unwrap()
                .left
                .as_ref()
                .unwrap()
                .v
                == 13
        );
        assert!(
            x.root
                .as_ref()
                .unwrap()
                .right
                .as_ref()
                .unwrap()
                .right
                .as_ref()
                .unwrap()
                .v
                == 17
        );
    }
}
