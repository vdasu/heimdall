// SPDX-License-Identifier: GPL-2.0
//
// Placeholder main.rs for the deterministic translation workspace.
// run_translation.py overwrites this file with the LLM's Rust translation
// before invoking `cargo build`. Kept here only so the workspace is in a
// buildable shape immediately after checkout.
#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
