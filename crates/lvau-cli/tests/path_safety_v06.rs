use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

fn lvau() -> Command {
    Command::cargo_bin("lvau-cli").unwrap()
}

#[test]
fn force_never_allows_encrypting_over_the_input_file() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let password = dir.path().join("password.txt");
    fs::write(&input, b"preserve me").unwrap();
    fs::write(&password, b"password\n").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
    }

    lvau()
        .args([
            "encrypt",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            input.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--profile",
            "fast",
            "--force",
        ])
        .assert()
        .failure();

    assert_eq!(fs::read(input).unwrap(), b"preserve me");
}

#[test]
fn force_never_allows_decrypting_over_the_capsule_itself() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let encrypted = dir.path().join("input.lvau");
    let password = dir.path().join("password.txt");
    fs::write(&input, b"plaintext").unwrap();
    fs::write(&password, b"password\n").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&password, fs::Permissions::from_mode(0o600)).unwrap();
    }

    lvau()
        .args([
            "encrypt",
            "--in-file",
            input.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--profile",
            "fast",
        ])
        .assert()
        .success();

    let before = fs::read(&encrypted).unwrap();
    lvau()
        .args([
            "decrypt",
            "--in-file",
            encrypted.to_str().unwrap(),
            "--out-file",
            encrypted.to_str().unwrap(),
            "--password-file",
            password.to_str().unwrap(),
            "--force",
        ])
        .assert()
        .failure();

    assert_eq!(fs::read(encrypted).unwrap(), before);
}
