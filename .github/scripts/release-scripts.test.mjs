import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
	updateCargoLockVersion,
	updateCargoTomlVersion,
	updateCargoVersionFiles,
} from "./bump-cargo-version.mjs";
import { computeReleasePlan } from "./release-plan.mjs";
import {
	bumpVersion,
	compareSemver,
	determineBump,
	isReleaseRelevantFile,
	parseManifest,
} from "./release-utils.mjs";

const releaseWorkflowText = readFileSync(
	new URL("../workflows/release.yml", import.meta.url),
	"utf8",
);
const releaseAssetsWorkflowText = readFileSync(
	new URL("../workflows/release-assets.yml", import.meta.url),
	"utf8",
);

test("parseManifest reads the package name and version", () => {
	const manifest = parseManifest(
		[
			"[package]",
			'name = "git-crypt"',
			'version = "0.2.3"',
			"",
			"[dependencies]",
			'clap = "4.5.60"',
		].join("\n"),
	);

	assert.deepEqual(manifest, {
		name: "git-crypt",
		version: "0.2.3",
	});
});

test("compareSemver and bumpVersion handle semantic version changes", () => {
	assert.equal(compareSemver("1.2.3", "1.2.3"), 0);
	assert.equal(compareSemver("1.2.4", "1.2.3"), 1);
	assert.equal(compareSemver("1.2.3", "1.3.0"), -1);
	assert.equal(bumpVersion("1.2.3", "patch"), "1.2.4");
	assert.equal(bumpVersion("1.2.3", "minor"), "1.3.0");
	assert.equal(bumpVersion("1.2.3", "major"), "2.0.0");
});

test("release file matcher only treats Rust sources and Cargo metadata as releasable", () => {
	assert.equal(isReleaseRelevantFile("src/main.rs"), true);
	assert.equal(isReleaseRelevantFile("Cargo.toml"), true);
	assert.equal(isReleaseRelevantFile("Cargo.lock"), true);
	assert.equal(isReleaseRelevantFile("README.md"), false);
	assert.equal(isReleaseRelevantFile(".github/workflows/ci.yml"), false);
});

test("determineBump prefers the highest semver label", () => {
	assert.equal(determineBump([]), "patch");
	assert.equal(
		determineBump([{ number: 1, labels: ["semver:minor"] }]),
		"minor",
	);
	assert.equal(
		determineBump([
			{ number: 1, labels: ["semver:minor"] },
			{ number: 2, labels: ["semver:major"] },
		]),
		"major",
	);
});

test("computeReleasePlan bootstraps when no semver tag exists", () => {
	const plan = computeReleasePlan({
		currentVersion: "0.2.3",
	});

	assert.equal(plan.releaseNeeded, true);
	assert.equal(plan.commitRequired, false);
	assert.equal(plan.mode, "bootstrap");
	assert.equal(plan.tag, "v0.2.3");
});

test("computeReleasePlan skips non-Rust-only changes", () => {
	const plan = computeReleasePlan({
		currentVersion: "0.2.3",
		latestTag: "v0.2.3",
		changedFiles: ["README.md", ".github/workflows/ci.yml"],
	});

	assert.equal(plan.releaseNeeded, false);
	assert.equal(plan.mode, "skip");
});

test("computeReleasePlan bumps patch by default for Rust changes", () => {
	const plan = computeReleasePlan({
		currentVersion: "0.2.3",
		latestTag: "v0.2.3",
		changedFiles: ["src/main.rs"],
		pullRequests: [{ number: 10, labels: [] }],
	});

	assert.equal(plan.releaseNeeded, true);
	assert.equal(plan.commitRequired, true);
	assert.equal(plan.mode, "version-bump");
	assert.equal(plan.tag, "v0.2.4");
	assert.equal(plan.bump, "patch");
});

test("computeReleasePlan respects semver labels", () => {
	const plan = computeReleasePlan({
		currentVersion: "0.2.3",
		latestTag: "v0.2.3",
		changedFiles: ["Cargo.toml"],
		pullRequests: [{ number: 11, labels: ["semver:minor"] }],
	});

	assert.equal(plan.tag, "v0.3.0");
	assert.equal(plan.bump, "minor");
});

test("computeReleasePlan reuses a manifest version that is already ahead of the latest tag", () => {
	const plan = computeReleasePlan({
		currentVersion: "0.2.4",
		latestTag: "v0.2.3",
		changedFiles: ["src/main.rs"],
	});

	assert.equal(plan.releaseNeeded, true);
	assert.equal(plan.commitRequired, false);
	assert.equal(plan.mode, "manifest-ahead");
	assert.equal(plan.tag, "v0.2.4");
});

test("computeReleasePlan can recover from an existing head tag", () => {
	const plan = computeReleasePlan({
		currentVersion: "0.2.4",
		headTag: "v0.2.4",
		latestTag: "v0.2.4",
	});

	assert.equal(plan.releaseNeeded, true);
	assert.equal(plan.commitRequired, false);
	assert.equal(plan.mode, "existing-head-tag");
	assert.equal(plan.tag, "v0.2.4");
});

test("Cargo version updates change only the root package entries", () => {
	const cargoTomlText = [
		"[package]",
		'name = "git-crypt"',
		'version = "0.2.3"',
		"",
		"[dependencies]",
		'clap = { version = "4.5.60", features = ["derive"] }',
	].join("\n");
	const cargoLockText = [
		"version = 4",
		"",
		"[[package]]",
		'name = "dep"',
		'version = "1.0.0"',
		"",
		"[[package]]",
		'name = "git-crypt"',
		'version = "0.2.3"',
	].join("\n");

	const updated = updateCargoVersionFiles({
		cargoTomlText,
		cargoLockText,
		nextVersion: "0.2.4",
	});

	assert.match(updated.cargoTomlText, /version = "0\.2\.4"/u);
	assert.match(
		updated.cargoLockText,
		/name = "git-crypt"\nversion = "0\.2\.4"/u,
	);
	assert.match(updated.cargoLockText, /name = "dep"\nversion = "1\.0\.0"/u);
});

test("individual Cargo update helpers reject missing package metadata", () => {
	assert.match(
		updateCargoTomlVersion('[package]\nversion = "0.2.3"\n', "0.2.4"),
		/0\.2\.4/u,
	);
	assert.match(
		updateCargoLockVersion(
			'[[package]]\nname = "git-crypt"\nversion = "0.2.3"\n',
			"git-crypt",
			"0.2.4",
		),
		/version = "0\.2\.4"/u,
	);
});

test("release workflow delegates asset publishing to the reusable release-assets workflow", () => {
	assert.match(
		releaseWorkflowText,
		/release_assets:[\s\S]*uses:\s+\.\/\.github\/workflows\/release-assets\.yml/u,
	);
	assert.match(
		releaseWorkflowText,
		/with:[\s\S]*tag:\s+\$\{\{\s*needs\.release\.outputs\.tag\s*\}\}/u,
	);
});

test("release-assets workflow is reusable or manually dispatched instead of listening for published releases", () => {
	assert.match(releaseAssetsWorkflowText, /workflow_call:[\s\S]*tag:/u);
	assert.match(releaseAssetsWorkflowText, /workflow_dispatch:[\s\S]*tag:/u);
	assert.doesNotMatch(releaseAssetsWorkflowText, /\n\s*release:\n/u);
});

test("release-assets workflow normalizes tag-like dispatch input before checkout and upload", () => {
	assert.match(
		releaseAssetsWorkflowText,
		/resolve_tag:[\s\S]*RAW_TAG:\s+\$\{\{\s*inputs\.tag\s*\|\|\s*github\.event\.inputs\.tag\s*\}\}/u,
	);
	assert.match(releaseAssetsWorkflowText, /\$\{tag#refs\/tags\/\}/u);
	assert.match(releaseAssetsWorkflowText, /\$\{tag#tag=\}/u);
	assert.match(
		releaseAssetsWorkflowText,
		/build:[\s\S]*needs:\s+resolve_tag[\s\S]*ref:\s+\$\{\{\s*needs\.resolve_tag\.outputs\.tag\s*\}\}/u,
	);
	assert.match(
		releaseAssetsWorkflowText,
		/TAG:\s+\$\{\{\s*needs\.resolve_tag\.outputs\.tag\s*\}\}/u,
	);
});
