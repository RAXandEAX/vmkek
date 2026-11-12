use super::*;

fn scope() -> BlockScope {
    BlockScope {
        app: [1; 16],
        build: [2; 16],
        function: [3; 16],
        generation: [4; 16],
        level: 1,
        purpose: BlockPurpose::Bytecode,
    }
}

#[test]
fn each_scope_field_and_block_coordinate_separates_keys() {
    let master = MasterSecret(Zeroizing::new([0; AEAD_KEY_LEN]));
    let scope = scope();
    let salt = [0; 32];
    let key = master.scope(scope).unwrap().block_key(&salt, 0).unwrap();
    for other in [
        BlockScope {
            app: [5; 16],
            ..scope
        },
        BlockScope {
            build: [5; 16],
            ..scope
        },
        BlockScope {
            function: [5; 16],
            ..scope
        },
        BlockScope {
            generation: [5; 16],
            ..scope
        },
        BlockScope { level: 2, ..scope },
        BlockScope {
            purpose: BlockPurpose::Dispatcher,
            ..scope
        },
    ] {
        let other = master.scope(other).unwrap();
        assert!(key.as_ref() != other.block_key(&salt, 0).unwrap().as_ref());
    }
    let scoped = master.scope(scope).unwrap();
    assert!(key.as_ref() != scoped.block_key(&[1; 32], 0).unwrap().as_ref());
    assert!(key.as_ref() != scoped.block_key(&salt, 1).unwrap().as_ref());
    assert!(master.scope(BlockScope { level: 0, ..scope }).is_err());
    assert!(master.scope(BlockScope { level: 5, ..scope }).is_err());
}

#[test]
fn fresh_build_secrets_are_independent_for_the_same_scope() {
    let scope = scope();
    let first = MasterSecret::generate().unwrap().scope(scope).unwrap();
    let next = MasterSecret::generate().unwrap().scope(scope).unwrap();
    assert!(first.key.as_ref() != next.key.as_ref());
}

#[test]
fn new_artifacts_get_independent_build_and_generation_ids() {
    let template = scope();
    let make = || {
        BlockScope::for_new_build(
            template.app,
            template.function,
            template.level,
            template.purpose,
        )
        .unwrap()
    };
    let first = make();
    let second = make();
    assert_eq!(first.app, second.app);
    assert_eq!(first.function, second.function);
    assert_ne!(first.build, second.build);
    assert_ne!(first.generation, second.generation);
}
