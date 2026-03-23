use std::collections::BTreeMap;

use crate::{
    Error, SetupArguments, apply_setup_plan, build_setup_plan, tests::util::TestRepositoryBuilder,
};

fn collect_changes(plan: &crate::SetupPlan) -> BTreeMap<String, Option<String>> {
    plan.gitconfig_changes
        .iter()
        .map(|change| (change.key, change.new_value))
        .collect()
}

#[test]
fn setup_必要なgitドライバ設定を書き込む() {
    let repo = TestRepositoryBuilder::new().build();
    let args = SetupArguments {
        public_key: None,
        private_key: None,
        encryption_key_id: None,
        encryption_path_regex: Some("^secret/.*".into()),
        filter_name: None,
        yes: true,
        force: false,
        dry_run: false,
    };

    let mut config = repo.context().repo.repo.config().unwrap();
    let plan = build_setup_plan(&config, b"", &args, &repo.context().repo).unwrap();
    let changes = collect_changes(&plan);

    assert_eq!(
        changes.get("filter.crypt.clean"),
        Some(&Some("git-crypt clean %f".into()))
    );
    assert_eq!(
        changes.get("filter.crypt.smudge"),
        Some(&Some("git-crypt smudge %f".into()))
    );
    assert_eq!(
        changes.get("filter.crypt.process"),
        Some(&Some("git-crypt process".into()))
    );
    assert_eq!(
        changes.get("filter.crypt.required"),
        Some(&Some("true".into()))
    );
    assert_eq!(
        changes.get("diff.crypt.textconv"),
        Some(&Some("git-crypt textconv".into()))
    );
    assert_eq!(
        changes.get("merge.crypt.driver"),
        Some(&Some("git-crypt merge %O %A %B %L %P".into()))
    );

    let gitattributes_path = repo.path().join(".gitattributes");
    apply_setup_plan(&plan, &mut config, &gitattributes_path).unwrap();

    assert_eq!(
        config.get_string("filter.crypt.process").unwrap(),
        "git-crypt process"
    );
    assert_eq!(
        config.get_string("merge.crypt.driver").unwrap(),
        "git-crypt merge %O %A %B %L %P"
    );

    let gitattributes = std::fs::read_to_string(gitattributes_path).unwrap();
    assert!(gitattributes.contains("* filter=crypt diff=crypt merge=crypt"));
    assert!(gitattributes.contains(".gitattributes filter= diff= merge="));
}

#[test]
fn setup_yesは不正な暗号化キーidを拒否する() {
    let repo = TestRepositoryBuilder::new().build();
    let config = repo.context().repo.repo.config().unwrap();
    let args = SetupArguments {
        public_key: None,
        private_key: None,
        encryption_key_id: Some("DEADBEEF".into()),
        encryption_path_regex: None,
        filter_name: None,
        yes: true,
        force: false,
        dry_run: false,
    };

    assert!(matches!(
        build_setup_plan(&config, b"", &args, &repo.context().repo),
        Err(Error::Setup)
    ));
}

#[test]
fn setup_yesは不正な正規表現を拒否する() {
    let repo = TestRepositoryBuilder::new().build();
    let config = repo.context().repo.repo.config().unwrap();
    let args = SetupArguments {
        public_key: None,
        private_key: None,
        encryption_key_id: None,
        encryption_path_regex: Some("[".into()),
        filter_name: None,
        yes: true,
        force: false,
        dry_run: false,
    };

    assert!(matches!(
        build_setup_plan(&config, b"", &args, &repo.context().repo),
        Err(Error::Setup)
    ));
}

#[test]
fn setup_yesは不正なfilter名を拒否する() {
    let repo = TestRepositoryBuilder::new().build();
    let config = repo.context().repo.repo.config().unwrap();
    let args = SetupArguments {
        public_key: None,
        private_key: None,
        encryption_key_id: None,
        encryption_path_regex: None,
        filter_name: Some("-invalid".into()),
        yes: true,
        force: false,
        dry_run: false,
    };

    assert!(matches!(
        build_setup_plan(&config, b"", &args, &repo.context().repo),
        Err(Error::Setup)
    ));
}
