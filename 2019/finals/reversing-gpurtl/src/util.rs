// Copyright 2019 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[derive(Clone, Debug)]
#[must_use = "iterator adaptors are lazy and do nothing unless consumed"]
pub struct TakePad<I: Iterator> {
    inner: I,
    padding: I::Item,
    remaining: usize,
}

impl<I> Iterator for TakePad<I>
where
    I: Iterator,
    I::Item: Clone,
{
    type Item = I::Item;
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining > 0 {
            self.remaining -= 1;
            self.inner.next().or(Some(self.padding.clone()))
        } else {
            None
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl<I> ExactSizeIterator for TakePad<I>
where
    I: Iterator,
    I::Item: Clone,
{
}

pub trait IteratorExtensions: Iterator {
    fn take_pad(self, n: usize, padding: Self::Item) -> TakePad<Self>
    where
        Self::Item: Clone,
        Self: Sized,
    {
        TakePad {
            inner: self,
            padding: padding,
            remaining: n,
        }
    }
}

impl<T: ?Sized> IteratorExtensions for T where T: Iterator {}

pub fn bitstream_to_bytes<'a>(
    bs: impl IntoIterator<Item = bool> + 'a,
) -> impl Iterator<Item = u8> + 'a {
    use itertools::Itertools;
    bs.into_iter().batching(|i| {
        let mut i = i.peekable();
        match i.peek() {
            Some(_) => Some(
                i.take(8)
                    .fold((0, 0), |(i, r), b| (i + 1, r | (b as u8) << (7 - i)))
                    .1,
            ),
            None => None,
        }
    })
}

pub fn bytes_to_bitstream<'a>(
    bs: impl IntoIterator<Item = u8> + 'a,
) -> impl Iterator<Item = bool> + 'a {
    bs.into_iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 0x1 == 1))
}
