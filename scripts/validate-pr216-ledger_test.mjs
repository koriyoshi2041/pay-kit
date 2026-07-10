#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  getSourceInventory,
  validateLedger,
} from "./validate-pr216-ledger.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ledger = JSON.parse(
  readFileSync(resolve(repoRoot, ".github/delivery/pr216-ledger.json"), "utf8"),
);
const inventory = getSourceInventory();

validateLedger(ledger, inventory);

function expectFailure(name, mutate, pattern) {
  const candidate = structuredClone(ledger);
  mutate(candidate);
  assert.throws(() => validateLedger(candidate, inventory), pattern, name);
}

expectFailure(
  "same-count commit substitution fails",
  (candidate) => {
    candidate.commits[0].sha = "0000000000000000000000000000000000000000";
  },
  /authoritative set digest mismatch/,
);
expectFailure(
  "same-count path substitution fails",
  (candidate) => {
    candidate.paths[0].path = "substituted/path.txt";
  },
  /authoritative set digest mismatch/,
);
expectFailure(
  "unknown status fails",
  (candidate) => {
    candidate.commits[0].status = "done";
  },
  /status must be one of/,
);
expectFailure(
  "evidence is mandatory",
  (candidate) => {
    candidate.commits[0].evidence = [];
  },
  /evidence must not be empty/,
);
expectFailure(
  "missing records require owners",
  (candidate) => {
    delete candidate.commits[0].owner;
  },
  /owner must be a string/,
);
expectFailure(
  "missing records require follow-ups",
  (candidate) => {
    delete candidate.paths.find((record) => record.status === "missing")
      .followUp;
  },
  /followUp must be a string/,
);
expectFailure(
  "integrated blob substitution fails",
  (candidate) => {
    const integrated = candidate.paths.find(
      (record) => record.status === "integrated",
    );
    integrated.evidence[0].deliveryBlob =
      "0000000000000000000000000000000000000000";
  },
  /delivery blob evidence is stale/,
);
expectFailure(
  "status summaries cannot drift",
  (candidate) => {
    candidate.summary.commits.missing -= 1;
  },
  /commit status summary is stale/,
);

console.log("validate-pr216-ledger_test: PASS");
