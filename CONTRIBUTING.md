# 🤝 Contributing to Paranoid Helper

Thanks for considering a contribution. This file is short on purpose — read it once, then go break things.

## 🧪 Before You Open a PR

1. **Fork + branch.** Branch name like `feat/wpa3-sae` or `fix/arp-race`.
2. **Build clean.** `xcodebuild -target IPscanner.helper -configuration Release` must succeed.
3. **No new warnings.** Swift 5.9 strict warnings stay clean.
4. **Comments in code can be English or Italian** — both are accepted (the parent project uses Italian, but contributors aren't expected to).
5. **One PR = one concern.** Don't bundle a refactor with a feature.

## 🔐 Security Bugs

**Do not open public issues for security flaws.** Email `andreapiani.dev@gmail.com` with `[SECURITY]` in the subject, or use [GitHub Security Advisories](https://github.com/andreapianidev/paranoid-macOS-security-helper/security/advisories/new).

Things we consider security-critical:
- Privilege escalation beyond the documented `executeCommand` whitelist
- XPC code-sign verification bypass
- Path traversal / symlink escape in `validatePath`
- Memory corruption in the C bridge (`pcap_bridge.c`, `raw_socket.c`)

## 🎁 The TestFlight Reward

After your **first merged PR** (any size, as long as it's substantive — not a typo fix), email `andreapiani.dev@gmail.com` from the email associated with your GitHub account. We'll send a TestFlight invite to the full Paranoid macOS app. No expiry games, no upsells.

## 📋 What We're Looking For

See the "We're Hiring (Contributors)" section in the [README](README.md). High-priority asks:

- Unit / integration tests (currently zero — pick any operation and add tests)
- Swift 6 strict concurrency migration
- WPA3 SAE handshake support in `HandshakeCaptureOperation`
- Better libpcap BPF filters for `passiveDiscovery`
- Documentation: sequence diagrams for the XPC protocol

## 💬 Questions

Open a [Discussion](https://github.com/andreapianidev/paranoid-macOS-security-helper/discussions) or email directly. We don't do Discord — sorry.
