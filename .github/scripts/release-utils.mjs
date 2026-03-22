export function parseSemver(version) {
	const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
	if (!match) {
		throw new Error(`Invalid semver version: ${version}`);
	}

	return {
		major: Number(match[1]),
		minor: Number(match[2]),
		patch: Number(match[3]),
	};
}

export function compareSemver(leftVersion, rightVersion) {
	const left = parseSemver(leftVersion);
	const right = parseSemver(rightVersion);

	for (const key of ["major", "minor", "patch"]) {
		if (left[key] > right[key]) {
			return 1;
		}
		if (left[key] < right[key]) {
			return -1;
		}
	}

	return 0;
}

export function bumpVersion(version, bump) {
	const parsed = parseSemver(version);

	switch (bump) {
		case "major":
			return `${parsed.major + 1}.0.0`;
		case "minor":
			return `${parsed.major}.${parsed.minor + 1}.0`;
		case "patch":
			return `${parsed.major}.${parsed.minor}.${parsed.patch + 1}`;
		default:
			throw new Error(`Unsupported version bump: ${bump}`);
	}
}

export function isReleaseRelevantFile(filePath) {
	return (
		filePath === "Cargo.toml" ||
		filePath === "Cargo.lock" ||
		filePath.endsWith(".rs")
	);
}

export function determineBump(pullRequests) {
	const labels = new Set(
		pullRequests.flatMap((pullRequest) => pullRequest.labels ?? []),
	);

	if (labels.has("semver:major")) {
		return "major";
	}

	if (labels.has("semver:minor")) {
		return "minor";
	}

	return "patch";
}

export function parseManifest(cargoTomlText) {
	const lines = cargoTomlText.split(/\r?\n/u);
	let inPackage = false;
	let name = null;
	let version = null;

	for (const line of lines) {
		if (line.startsWith("[")) {
			inPackage = line === "[package]";
			continue;
		}

		if (!inPackage) {
			continue;
		}

		const nameMatch = /^name = "([^"]+)"$/u.exec(line);
		if (nameMatch) {
			name = nameMatch[1];
			continue;
		}

		const versionMatch = /^version = "([^"]+)"$/u.exec(line);
		if (versionMatch) {
			version = versionMatch[1];
		}
	}

	if (!name || !version) {
		throw new Error("Failed to read package metadata from Cargo.toml");
	}

	return { name, version };
}
