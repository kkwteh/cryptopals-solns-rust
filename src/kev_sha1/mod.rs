//! Vendored copy of sha1 crate

#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

mod compress;
mod consts;

use crate::kev_sha1::compress::compress;
use crate::kev_sha1::consts::{H, STATE_LEN};
use block_buffer::BlockBuffer;
use digest::consts::{U20, U64};
pub use digest::{self, Digest};
use digest::{BlockInput, FixedOutputDirty, Reset, Update};

/// Structure representing the state of a SHA-1 computation
#[derive(Clone)]
pub struct Sha1 {
    h: [u32; STATE_LEN],
    len: u64,
    buffer: BlockBuffer<U64>,
}

impl Default for Sha1 {
    fn default() -> Self {
        Sha1 {
            h: H,
            len: 0u64,
            buffer: Default::default(),
        }
    }
}

impl BlockInput for Sha1 {
    type BlockSize = U64;
}

impl Update for Sha1 {
    fn update(&mut self, input: impl AsRef<[u8]>) {
        let input = input.as_ref();
        // Assumes that `length_bits<<3` will not overflow
        self.len += input.len() as u64;
        let state = &mut self.h;
        self.buffer.input_blocks(input, |d| compress(state, d));
    }
}

impl FixedOutputDirty for Sha1 {
    type OutputSize = U20;

    fn finalize_into_dirty(&mut self, out: &mut digest::Output<Self>) {
        let s = &mut self.h;
        let l = self.len << 3;
        self.buffer
            .len64_padding_be(l, |d| compress(s, core::slice::from_ref(d)));
        for (chunk, v) in out.chunks_exact_mut(4).zip(self.h.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl Reset for Sha1 {
    fn reset(&mut self) {
        self.h = H;
        self.len = 0;
        self.buffer.reset();
    }
}

opaque_debug::implement!(Sha1);
digest::impl_write!(Sha1);
