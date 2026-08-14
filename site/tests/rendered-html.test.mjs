import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("builds a self-contained RemedyFabric evidence dashboard", async () => {
  const html = await readFile(new URL("../dist/index.html", import.meta.url), "utf8");
  assert.match(html, /Faulty-Agent-resistant recovery infrastructure/);
  assert.match(html, /20,748/);
  assert.match(html, /30 merged OSS PR identities/);
  assert.match(html, /AgentTeams/);
  assert.match(html, /(?:PRE-FREEZE EVIDENCE SET COMPLETE|EVIDENCE BUILD IN PROGRESS)/);
  assert.match(html, /This neutral status is recomputed/);
  assert.match(html, /It never asserts final submission readiness/);
  assert.match(html, /github.com\/Oxygen56\/remedyfabric/);
  assert.doesNotMatch(html, /<script[^>]+src=|<link[^>]+https?:|<img[^>]+https?:/i);
});
