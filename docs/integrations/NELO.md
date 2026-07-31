# Nelo integration

[Nelo](https://github.com/lasder-ca/Nelo) can run `lvau-cli` as request-owned work. Its [`lvau-service` example](https://github.com/lasder-ca/Nelo/tree/main/examples/lvau-service) accepts a bounded request body, encrypts it with Lvau, and returns a `.lvau` capsule.

The integration is designed around process and file ownership rather than a hidden in-process bridge:

- Nelo starts `lvau-cli` through `context.fork()`;
- request cancellation terminates the child process;
- plaintext and encrypted output live in a request-owned temporary directory;
- the directory is removed when the handler scope closes;
- the password is read from a protected local file;
- the service selects the `balanced` profile explicitly;
- Lvau stderr is kept out of the HTTP response.

## Prerequisites

Build Lvau and prepare a password file:

```sh
cargo build --locked --release --package lvau-cli
printf '%s' 'replace-with-a-strong-passphrase' > password.txt
chmod 600 password.txt
```

Then set these variables in the Nelo example:

```sh
export LVAU_CLI="$PWD/target/release/lvau-cli"
export LVAU_PASSWORD_FILE="$PWD/password.txt"
```

On Windows, restrict the password file ACL to the account running the service. Lvau checks broad secret-file permissions automatically on Unix, but it cannot validate an overly permissive Windows ACL.

## Security boundary

This integration prevents an abandoned HTTP request from leaving an unowned encryption process or plaintext work directory behind. It does not make external process execution transactional and is not a complete public file-encryption service.

For an internet-facing deployment, add authentication, authorization, rate limits, request and concurrency quotas, process isolation, execution deadlines, and audit records that never include plaintext or credentials. Keep password files and private keys outside the application repository. Avoid exposing a general-purpose decrypt endpoint unless the threat model requires one.
