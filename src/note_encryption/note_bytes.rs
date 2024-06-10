//! Utilities for handling note bytes in the Orchard protocol.
//!
//! This module provides structures and traits for working with fixed-size arrays of bytes,
//! which represent various components of notes in the Orchard protocol.

/// Represents a fixed-size array of bytes for note components.
#[derive(Clone, Copy, Debug)]
pub struct NoteBytesData<const N: usize>(pub [u8; N]);

impl<const N: usize> AsRef<[u8]> for NoteBytesData<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for NoteBytesData<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

// FIXME: consider implementing and using TryFrom instead
impl<const N: usize> From<&[u8]> for NoteBytesData<N> {
    fn from(s: &[u8]) -> Self {
        Self(s.try_into().unwrap())
    }
}

impl<const N: usize> From<(&[u8], &[u8])> for NoteBytesData<N> {
    fn from(s: (&[u8], &[u8])) -> Self {
        Self([s.0, s.1].concat().try_into().unwrap())
    }
}

/// Provides a unified interface for handling fixed-size byte arrays used in Orchard note encryption.
pub trait NoteBytes:
    AsRef<[u8]>
    + AsMut<[u8]>
    + for<'a> From<&'a [u8]>
    + for<'a> From<(&'a [u8], &'a [u8])>
    + Clone
    + Copy
{
}

impl<const N: usize> NoteBytes for NoteBytesData<N> {}
