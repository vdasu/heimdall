// SPDX-License-Identifier: GPL-2.0
//
// Placeholder main.rs for the agentic (Claude Code) translation workspace.
// claude_code_translate.sh hands the agent the C source and a write target
// of aya-ebpf-claude/src/main.rs; the agent overwrites this file in the
// course of producing a verified Rust translation. Kept here only so the
// workspace builds cleanly after checkout.
#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
