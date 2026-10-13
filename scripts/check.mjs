// Living Holograms check: plain Node, no dependencies.
// It extracts the exact core script from play/portal.html and checks canonical JSON,
// SHA-256, a fixed three-pass chain, replay, and tamper detection. It also checks the
// paper against its writing rules and its required links.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
let passed = 0, failed = 0;
function check(name, ok, detail = "") {
  if (ok) { passed++; console.log("  ok   " + name); }
  else { failed++; console.log("  FAIL " + name + (detail ? "  (" + detail + ")" : "")); }
}

// ---------- load the demo's own core ----------
const html = readFileSync(join(root, "play/portal.html"), "utf8");
const m = html.match(/<script id="hologram-core">([\s\S]*?)<\/script>/);
if (!m) { console.log("FAIL could not find <script id=\"hologram-core\"> in play/portal.html"); process.exit(1); }
new Function(m[1])();
const C = globalThis.HologramCore;

console.log("canonical JSON");
check("sorted keys, no whitespace", C.canon({ b: 1, a: [true, null, "x"] }) === '{"a":[true,null,"x"],"b":1}');
check("string escapes", C.canon("q\"\\\n\u0001") === '"q\\"\\\\\\n\\u0001"');
check("non-ASCII kept as UTF-8, sorted by code unit", C.canon({ "é": 1, z: 2, A: 3 }) === '{"A":3,"z":2,"é":1}');
check("nested objects and empty containers", C.canon({ o: { y: [], x: {} } }) === '{"o":{"x":{},"y":[]}}');
check("negative integer and zero", C.canon([-3, 0, -0]) === "[-3,0,0]");
const throws = (fn) => { try { fn(); return false; } catch { return true; } };
check("rejects floats", throws(() => C.canon(1.5)));
check("rejects undefined values", throws(() => C.canon({ a: undefined })));
check("rejects unsafe integers", throws(() => C.canon(2 ** 60)));

console.log("SHA-256 and H(tag, value)");
check("FIPS 180-4 vector sha256('abc')",
  (await C.sha256hex("abc")) === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
const nodeH = (tag, value) => createHash("sha256").update(tag + "\n" + C.canon(value), "utf8").digest("hex");
const sample = { schema: "x", n: 7, list: ["é", true, null] };
check("H(particle) matches node:crypto", (await C.H(C.TAG_PARTICLE, sample)) === nodeH("rapp/1:particle", sample));
check("H(wave) matches node:crypto", (await C.H(C.TAG_WAVE, sample)) === nodeH("rapp/1:wave", sample));
check("tags separate domains", (await C.H(C.TAG_PARTICLE, sample)) !== (await C.H(C.TAG_WAVE, sample)));
check("known vector H('rapp/1:particle', {})",
  (await C.H(C.TAG_PARTICLE, {})) === createHash("sha256").update("rapp/1:particle\n{}").digest("hex"));

console.log("caller view and validation");
const view = C.callerView(C.lensByName("Wander"));
check("caller view has no perform()", !("perform" in view) && Object.keys(view).sort().join() === "description,name,parameters");
check("every parameter has a description", C.LENSES.every((l) => Object.values(l.parameters.properties).every((p) => typeof p.description === "string" && p.description.length > 0)));
check("rejects out-of-range params", C.validate(C.lensByName("Wander").parameters, { direction: "east", distance: 99 }).length === 1);
check("rejects unknown enum", C.validate(C.lensByName("Mood").parameters, { mood: "angry", cause: "x" }).length === 1);

console.log("fixed three-pass chain");
const log = (pokes) => ({ ticks: 40, pokes, events: pokes ? [{ t: 7, x: 10, y: 20 }] : [], final: { x: 51, y: 49 } });
let chain = [await C.genesis()];
let rejected = false;
try { await C.pass(chain, "Wander", { direction: "up", distance: 3 }, { id: "t", kind: "process" }, log(0)); } catch { rejected = true; }
check("invalid params append nothing", rejected && chain.length === 1);
chain = await C.pass(chain, "Wander", { direction: "east", distance: 10 }, { id: "checker", kind: "process" }, log(0));
chain = await C.pass(chain, "Mood", { mood: "startled", cause: "was poked 3 times" }, { id: "checker", kind: "process" }, log(3));
chain = await C.pass(chain, "Remember", { memory: "the east side is loud", importance: 4 }, { id: "checker", kind: "person" }, log(0));
const head = chain[3].payload.object;
check("chain has genesis plus 3 tiles", chain.length === 4 && chain.map((f) => f.seq).join() === "0,1,2,3");
check("perform is deterministic: expected head object",
  C.canon(head) === C.canon({ schema: "living-holograms/creature-1", name: "Mote", x: 60, y: 50, mood: "startled", mood_cause: "was poked 3 times", energy: 61, memory: [{ text: "the east side is loud", importance: 4, pass: 3 }], felt: { pokes: 0 }, pass: 3 }),
  C.canon(head));
check("slush carried: Mood tile received Wander's trail", C.canon(chain[2].payload.slush_in.from_tile) === '{"last":"Wander","trail":[[60,50]]}');
check("reflex log sloshed into slush_in", chain[2].payload.slush_in.reflex.pokes === 3);
check("Remember drops the trail (memory by selection)", !("trail" in chain[3].payload.data_slush));
check("derived_from equals previous frame_hash", chain.slice(1).every((f, i) => f.payload.derived_from === chain[i].frame_hash));
const r1 = await C.replay(chain);
check("replay passes on the untouched chain", r1.ok, JSON.stringify(r1.results.filter((r) => !r.ok)));
const again = [await C.genesis()];
check("genesis is reproducible", again[0].frame_hash === chain[0].frame_hash);

console.log("tamper");
const forged = await C.tamper(chain);
const r2 = await C.replay(forged);
const headRes = r2.results[3];
check("replay fails after tamper", !r2.ok);
check("forged head still passes its own hash checks", headRes.checks.filter((c) => /re-derives$/.test(c.name) && !/params/.test(c.name)).every((c) => c.ok));
check("only the replay check catches the resealed forgery",
  headRes.checks.filter((c) => !c.ok).map((c) => c.name).join() === "replay: perform() reproduces object and data_slush");
const midEdit = JSON.parse(JSON.stringify(chain));
midEdit[1].payload.object.energy = 99; // edit without resealing
const r3 = await C.replay(midEdit);
check("unsealed mid-chain edit fails hash and replay", !r3.results[1].ok && r3.results[1].checks.find((c) => c.name === "payload particle re-derives").ok === false);
const swapped = JSON.parse(JSON.stringify(chain));
swapped[2].payload.slush_in.reflex.pokes = 0;
check("editing slush_in breaks the tile", !(await C.replay(swapped)).ok);

console.log("reflexes");
const src = C.compileReflex(head);
const rx = C.makeReflex(src, 4000);
const a = rx.step(1, []), b = rx.step(2, [{ x: 50, y: 50 }]);
check("routine parses and runs within budget", a.ops <= 4000 && b.ops <= 4000);
check("compiled routine reflects the present", /\(home 60 50\)/.test(src) && /\(flee 24\)/.test(src));
check("budget is enforced", throws(() => C.makeReflex(src, 5).step(1, [{ x: 1, y: 1 }])));

// ---------- the paper ----------
console.log("paper");
const paper = readFileSync(join(root, "paper.html"), "utf8");
const text = paper.replace(/<script[\s\S]*?<\/script>/g, " ").replace(/<style[\s\S]*?<\/style>/g, " ").replace(/<[^>]+>/g, " ").replace(/&[a-z#0-9]+;/gi, " ");
const count = (t) => t.split(/\s+/).filter((w) => /[A-Za-z0-9]/.test(w)).length;
const words = count(text);
const bodyStart = text.indexOf("Abstract"), bodyEnd = text.lastIndexOf("8 · References");
const bodyWords = count(text.slice(bodyStart, bodyEnd));
console.log("  word count, Abstract through Conclusion: " + bodyWords + " (whole page incl. title, nav, references: " + words + ")");
check("body word count between 3,500 and 4,500", bodyStart > 0 && bodyEnd > bodyStart && bodyWords >= 3500 && bodyWords <= 4500, String(bodyWords));
for (const [file, body] of [["paper.html", paper], ["index.html", readFileSync(join(root, "index.html"), "utf8")], ["play/portal.html", html], ["README.md", readFileSync(join(root, "README.md"), "utf8")]]) {
  check(file + " has no em-dashes", !/—|&mdash;/.test(body));
}
const required = [
  "https://kody-w.github.io/frame-chains/paper.html",
  "https://github.com/users/kody-w/projects/1",
  "https://github.com/kody-w/rappterbook/pull/21376",
  "https://github.com/kody-w/rappterbook/pull/21381",
  "https://github.com/kody-w/rappterverse/pull/12678",
  "https://github.com/kody-w/dogg",
  "https://github.com/EricTechPro/super-board",
  "https://kody-w.github.io/localFirstTools/exhibitions/sound-studio/holographic-display-creator.html",
  "https://github.com/kody-w/rapp-1",
  "play/portal.html",
  "assets/at-a-glance.png"
];
for (const url of required) check("paper links " + url, paper.includes(url));
check("byline", paper.includes("Kody Wildfeuer · RapterBox LLC · First public disclosure: October 13, 2026"));
check("figure has alt text", /<img[^>]+src="assets\/at-a-glance.png"[^>]+alt="[^"]{20,}"/.test(paper));
for (const h of ["Abstract", "Introduction", "Substrate", "Design", "Reduction to practice", "Related work", "Limitations", "Conclusion", "References"]) {
  check("section: " + h, paper.includes(h));
}
const secretish = /(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_|sk-[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY)/;
check("no token-shaped strings in published files", ![paper, html].some((t) => secretish.test(t)));

console.log("\n" + passed + " passed, " + failed + " failed");
process.exit(failed ? 1 : 0);
