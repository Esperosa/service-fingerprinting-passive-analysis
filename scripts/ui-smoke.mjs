import { readFile } from "node:fs/promises";
import { JSDOM } from "jsdom";

const html = await readFile("ui/index.html", "utf8");
const css = await readFile("ui/styles.css", "utf8");
const js = await readFile("ui/app.js", "utf8");

if (!html.includes("id=\"app\"")) throw new Error("HTML neobsahuje očekávaný #app root.");
if (!css.includes("workspace-grid") || !css.includes("graph-surface") || !css.includes("audit-assistant-button") || !css.includes("overflow:hidden")) {
  throw new Error("CSS nevypadá jako viewport-first dashboard vrstva.");
}
if (/spider|jumping/.test(css) || /spider|jumping/.test(js)) {
  throw new Error("UI bundle obsahuje staré názvosloví nebo asset maskota.");
}
const fixedUnit = /\b-?\d+(?:\.\d+)?px\b/;
if (fixedUnit.test(css) || fixedUnit.test(js)) {
  throw new Error("UI bundle obsahuje pevné px jednotky místo responzivních rem/vw/vh jednotek.");
}
if (/font-size:\s*-?\d/i.test(css)) {
  throw new Error("UI CSS obsahuje pevné velikosti fontů místo responzivních typografických tokenů.");
}
if (/overflow-wrap:\s*anywhere|hyphens:\s*auto|word-break:\s*break-word/i.test(css)) {
  throw new Error("UI CSS obsahuje pravidla, která rozdělují slova.");
}
if (!js.includes("renderCenterStage") || !js.includes("renderRightStage") || !js.includes("buildGuide") || !js.includes("bindGraphInteractions")) {
  throw new Error("Bundlované JS neobsahuje očekávanou dashboard logiku.");
}

const dom = new JSDOM(html);
if (!dom.window.document.querySelector("#app")) throw new Error("index.html neobsahuje #app root.");
