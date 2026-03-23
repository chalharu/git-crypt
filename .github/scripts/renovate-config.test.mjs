import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const renovateConfig = JSON.parse(
	readFileSync(new URL("../../renovate.json", import.meta.url), "utf8"),
);

test("renovate config excludes first-party GitHub Actions without unsupported regex features", () => {
	const githubActionsRule = renovateConfig.packageRules.find((rule) =>
		rule.matchManagers?.includes("github-actions"),
	);

	assert.ok(githubActionsRule, "expected a github-actions package rule");
	assert.deepEqual(githubActionsRule.matchPackageNames, [
		"!/^actions\\//",
		"!/^github\\//",
	]);
	assert.equal(githubActionsRule.pinDigests, true);
});
