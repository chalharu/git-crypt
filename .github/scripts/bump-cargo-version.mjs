import fs from "node:fs";
import process from "node:process";
import { pathToFileURL } from "node:url";

import { parseManifest, parseSemver } from "./release-utils.mjs";

export function updateCargoTomlVersion(cargoTomlText, nextVersion) {
	parseSemver(nextVersion);

	const lines = cargoTomlText.split(/\r?\n/u);
	let inPackage = false;
	let updated = false;

	for (let index = 0; index < lines.length; index += 1) {
		const line = lines[index];
		if (line.startsWith("[")) {
			inPackage = line === "[package]";
			continue;
		}

		if (!inPackage || !/^version = "([^"]+)"$/u.test(line)) {
			continue;
		}

		lines[index] = `version = "${nextVersion}"`;
		updated = true;
		break;
	}

	if (!updated) {
		throw new Error("Failed to update Cargo.toml package version");
	}

	return `${lines.join("\n")}\n`;
}

export function updateCargoLockVersion(
	cargoLockText,
	packageName,
	nextVersion,
) {
	parseSemver(nextVersion);

	const lines = cargoLockText.split(/\r?\n/u);
	let inPackage = false;
	let packageMatched = false;
	let updated = false;

	for (let index = 0; index < lines.length; index += 1) {
		const line = lines[index];

		if (line === "[[package]]") {
			inPackage = true;
			packageMatched = false;
			continue;
		}

		if (!inPackage) {
			continue;
		}

		if (line.startsWith("[") && line !== "[[package]]") {
			inPackage = false;
			packageMatched = false;
			continue;
		}

		const nameMatch = /^name = "([^"]+)"$/u.exec(line);
		if (nameMatch) {
			packageMatched = nameMatch[1] === packageName;
			continue;
		}

		if (packageMatched && /^version = "([^"]+)"$/u.test(line)) {
			lines[index] = `version = "${nextVersion}"`;
			updated = true;
			break;
		}
	}

	if (!updated) {
		throw new Error(
			`Failed to update Cargo.lock package version for ${packageName}`,
		);
	}

	return `${lines.join("\n")}\n`;
}

export function updateCargoVersionFiles({
	cargoTomlText,
	cargoLockText,
	nextVersion,
}) {
	const manifest = parseManifest(cargoTomlText);
	return {
		cargoTomlText: updateCargoTomlVersion(cargoTomlText, nextVersion),
		cargoLockText: updateCargoLockVersion(
			cargoLockText,
			manifest.name,
			nextVersion,
		),
	};
}

function main() {
	const nextVersion = process.argv[2];
	if (!nextVersion) {
		throw new Error(
			"Usage: node .github/scripts/bump-cargo-version.mjs <version>",
		);
	}

	const cargoTomlText = fs.readFileSync("Cargo.toml", "utf8");
	const cargoLockText = fs.readFileSync("Cargo.lock", "utf8");
	const updated = updateCargoVersionFiles({
		cargoTomlText,
		cargoLockText,
		nextVersion,
	});

	fs.writeFileSync("Cargo.toml", updated.cargoTomlText);
	fs.writeFileSync("Cargo.lock", updated.cargoLockText);
	process.stdout.write(`${nextVersion}\n`);
}

if (
	process.argv[1] &&
	import.meta.url === pathToFileURL(process.argv[1]).href
) {
	try {
		main();
	} catch (error) {
		const message =
			error instanceof Error ? (error.stack ?? error.message) : String(error);
		console.error(message);
		process.exitCode = 1;
	}
}
