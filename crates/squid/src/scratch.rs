//! Internal scratch-arena management.
//!
//! Poulpy operations never heap-allocate on the hot path; instead every
//! operation accepts a `&mut Scratch<BE>` region sized by a companion
//! `*_tmp_bytes` query.  This module owns the `ScratchOwned<BE>` allocation
//! that lives inside [`Context`][crate::context::Context].
//!
//! Nothing in this module is part of the public API.

use poulpy_hal::{
    api::{ScratchOwnedAlloc, ScratchOwnedBorrow},
    layouts::ScratchOwned,
};

/// Owned scratch arena pinned to the `crate::backend::BE` CPU backend.
pub(crate) type Arena = ScratchOwned<crate::backend::BE>;

/// Allocate a scratch arena of `bytes` bytes.
pub(crate) fn new_arena(bytes: usize) -> Arena {
    ScratchOwned::alloc(bytes)
}

/// Borrow the inner `&mut Scratch<crate::backend::BE>` from an [`Arena`].
///
/// This is a thin re-export of `ScratchOwned::borrow` so call sites inside
/// `context.rs` do not need to import the HAL trait directly.
#[inline]
pub(crate) fn borrow(arena: &mut Arena) -> &mut poulpy_hal::layouts::Scratch<crate::backend::BE> {
    arena.borrow()
}
