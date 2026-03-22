import { execFileSync } from "node:child_process";
import fs from "node:fs";
import process from "node:process";
import { pathToFileURL } from "node:url";

import {
	bumpVersion,
	compareSemver,
	determineBump,
	isReleaseRelevantFile,
	parseManifest,
} from "./release-utils.mjs";

function runGit(args, { allowFailure = false } = {}) {
	try {
		return execFileSync("git", args, {
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
		}).trim();
	} catch (error) {
		if (allowFailure) {
			return "";
		}
		throw error;
	}
}

function getHeadTag() {
	const tags = runGit(
		[
			"tag",
			"--points-at",
			"HEAD",
			"--list",
			"v[0-9]*.[0-9]*.[0-9]*",
			"--sort=-v:refname",
		],
		{ allowFailure: true },
	)
		.split(/\r?\n/u)
		.filter(Boolean);

	return tags[0] ?? null;
}

function getLatestTag() {
	return (
		runGit(
			["describe", "--tags", "--abbrev=0", "--match", "v[0-9]*.[0-9]*.[0-9]*"],
			{ allowFailure: true },
		) || null
	);
}

function getChangedFiles(latestTag) {
	if (!latestTag) {
		return [];
	}

	return runGit(["diff", "--name-only", `${latestTag}..HEAD`], {
		allowFailure: true,
	})
		.split(/\r?\n/u)
		.filter(Boolean);
}

function getCommitRange(latestTag) {
	if (!latestTag) {
		return [];
	}

	return runGit(["rev-list", "--reverse", `${latestTag}..HEAD`], {
		allowFailure: true,
	})
		.split(/\r?\n/u)
		.filter(Boolean);
}

async function fetchPullRequestsForCommit(commitSha, repository, token) {
	if (!repository || !token) {
		return [];
	}

	const response = await fetch(
		`https://api.github.com/repos/${repository}/commits/${commitSha}/pulls`,
		{
			headers: {
				authorization: `Bearer ${token}`,
				accept: "application/vnd.github+json",
				"x-github-api-version": "2022-11-28",
			},
		},
	);

	if (!response.ok) {
		throw new Error(
			`Failed to load pull requests for ${commitSha}: ${response.status} ${response.statusText}`,
		);
	}

	const data = await response.json();
	return data.map((pullRequest) => ({
		number: pullRequest.number,
		labels: (pullRequest.labels ?? []).map((label) => label.name),
	}));
}

async function collectPullRequests(commitRange) {
	const repository = process.env.GITHUB_REPOSITORY;
	const token = process.env.GITHUB_TOKEN;
	const pullRequests = new Map();

	for (const commitSha of commitRange) {
		const entries = await fetchPullRequestsForCommit(
			commitSha,
			repository,
			token,
		);
		for (const pullRequest of entries) {
			if (!pullRequests.has(pullRequest.number)) {
				pullRequests.set(pullRequest.number, pullRequest);
			}
		}
	}

	return [...pullRequests.values()];
}

export function computeReleasePlan({
	currentVersion,
	headTag = null,
	latestTag = null,
	changedFiles = [],
	pullRequests = [],
}) {
	if (headTag) {
		return {
			releaseNeeded: true,
			commitRequired: false,
			mode: "existing-head-tag",
			version: headTag.slice(1),
			tag: headTag,
			headTag,
			latestTag,
			bump: null,
			relevantFiles: [],
			pullRequests,
		};
	}

	if (!latestTag) {
		return {
			releaseNeeded: true,
			commitRequired: false,
			mode: "bootstrap",
			version: currentVersion,
			tag: `v${currentVersion}`,
			headTag,
			latestTag,
			bump: null,
			relevantFiles: [],
			pullRequests,
		};
	}

	const latestVersion = latestTag.slice(1);
	const comparison = compareSemver(currentVersion, latestVersion);
	if (comparison < 0) {
		throw new Error(
			`Cargo version ${currentVersion} is behind the latest tag ${latestTag}`,
		);
	}

	if (comparison > 0) {
		return {
			releaseNeeded: true,
			commitRequired: false,
			mode: "manifest-ahead",
			version: currentVersion,
			tag: `v${currentVersion}`,
			headTag,
			latestTag,
			bump: null,
			relevantFiles: [],
			pullRequests,
		};
	}

	const relevantFiles = changedFiles.filter(isReleaseRelevantFile);
	if (relevantFiles.length === 0) {
		return {
			releaseNeeded: false,
			commitRequired: false,
			mode: "skip",
			version: null,
			tag: null,
			headTag,
			latestTag,
			bump: null,
			relevantFiles: [],
			pullRequests,
		};
	}

	const bump = determineBump(pullRequests);
	const version = bumpVersion(currentVersion, bump);

	return {
		releaseNeeded: true,
		commitRequired: true,
		mode: "version-bump",
		version,
		tag: `v${version}`,
		headTag,
		latestTag,
		bump,
		relevantFiles,
		pullRequests,
	};
}

export async function buildReleasePlan() {
	const cargoTomlText = fs.readFileSync("Cargo.toml", "utf8");
	const manifest = parseManifest(cargoTomlText);
	const headTag = getHeadTag();
	const latestTag = getLatestTag();
	const changedFiles = getChangedFiles(latestTag);
	const commitRange = getCommitRange(latestTag);
	const relevantFiles = changedFiles.filter(isReleaseRelevantFile);
	const pullRequests =
		headTag || !latestTag || relevantFiles.length === 0
			? []
			: await collectPullRequests(commitRange);

	return computeReleasePlan({
		currentVersion: manifest.version,
		headTag,
		latestTag,
		changedFiles,
		pullRequests,
	});
}

async function main() {
	const plan = await buildReleasePlan();
	process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
}

if (
	process.argv[1] &&
	import.meta.url === pathToFileURL(process.argv[1]).href
) {
	try {
		await main();
	} catch (error) {
		const message =
			error instanceof Error ? (error.stack ?? error.message) : String(error);
		console.error(message);
		process.exitCode = 1;
	}
}
