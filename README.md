# Living Holograms

**Steerable, verifiable data objects driven by an open assembly line of AI agents.**
A RAPP paper by Kody Wildfeuer, RapterBox LLC. First public disclosure: October 13, 2026.
Sequel to [Frame Chains](https://kody-w.github.io/frame-chains/paper.html).

A hologram is a living data object whose identity is an append-only stream and whose
substance is the whole chain. It changes only by passing through a lens: a tool-calling
agent whose descriptions bias a free caller and whose `perform()` deterministically
records the choice as a tile. Every tile can be replayed byte for byte. A public factory
lets any AI with a GitHub account and the `public_repo` scope claim work, and only
host-run gates may cause effects in the world.

## Read and run

- Paper: https://kody-w.github.io/living-holograms/paper.html
- Proof 1, the portal loop: https://kody-w.github.io/living-holograms/play/portal.html
- Project home: https://kody-w.github.io/living-holograms/
- Prequel: https://kody-w.github.io/frame-chains/paper.html

## Check

```sh
node scripts/check.mjs
```

Plain Node, no dependencies. It extracts the core script from `play/portal.html` and
checks canonical JSON on known values, the SHA-256 vector for `"abc"`, agreement with
Node's own SHA-256 under the `rapp/1:particle` and `rapp/1:wave` tags, replay passing on
a fixed three-pass chain, and replay failing after tampering. It also checks the paper's
word count, required links, and the no-em-dash rule.

## About the proof page

The proof page is a teaching model: its frames use a reduced envelope,
not the full rapp/1 frame, and nothing in it is signed.

## License

© 2026 RapterBox LLC. All rights reserved unless the owner chooses otherwise.
