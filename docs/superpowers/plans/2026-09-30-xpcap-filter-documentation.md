# xpcap Filter Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make xpcap's actual tcpdump-style filter vocabulary discoverable in the main, Chinese, English, and `-h` documentation.

**Architecture:** Keep the existing `pktbaffle` parser and cBPF validation unchanged. Add one canonical reference in `xpcap/README.md`, concise localized references, and representative help examples; tests compile the documented representative expressions.

**Tech Stack:** Rust, Clap, pktbaffle classic BPF, Markdown.

## Global Constraints

- Do not claim full tcpdump/libpcap compatibility; document the supported subset and runtime limits.
- Keep the XDP/XSK classic-BPF probe limit at 128 instructions.
- Do not touch unrelated worktree changes.

### Task 1: Canonical Filter Reference

**Files:**
- Modify: `/home/captain/tools/xpcap/README.md`

- [ ] Add a `Filter Syntax` section covering hosts/networks, ports/ranges, protocols, `src`/`dst`, boolean operators and precedence, Ethernet/EtherType, VLAN/MPLS/PPPoE, broadcast/multicast, length, raw byte access, TCP flag constants, and ICMP constants.
- [ ] Include runnable examples for each category and state shell quoting requirements.
- [ ] Document that this is the `pktbaffle` supported subset, that `-i any` PCAP filtering is userspace, and that XDP/XSK expressions must fit 128 classic-BPF instructions.

### Task 2: Localized Quick References

**Files:**
- Modify: `/home/captain/tools/docs/zh/xpcap/README.md`
- Modify: `/home/captain/tools/docs/en/xpcap/README.md`

- [ ] Add the same filter categories in concise Chinese and English sections.
- [ ] Link users to the canonical manual for the full examples and retain the stage/output limits.

### Task 3: Help and Regression Coverage

**Files:**
- Modify: `/home/captain/tools/xpcap/src/main.rs`

- [ ] Extend `after_help` with address, port-range, boolean, VLAN, length, raw TCP flag, and ICMP examples while keeping output compact.
- [ ] Extend `short_options_and_filter_examples` to assert the new examples appear and compile representative expressions from each category.

### Task 4: Verify and Commit

- [ ] Run `cargo fmt --manifest-path xpcap/Cargo.toml -- --check`.
- [ ] Run `make check-xpcap` and confirm tests, Clippy, and formatting pass.
- [ ] Run `git diff --check` and review only the intended files before committing.
