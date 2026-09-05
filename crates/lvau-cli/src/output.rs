use serde::Serialize;

pub const JSON_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct JsonEnvelope<'a, T: Serialize> {
    schema_version: u32,
    command: &'a str,
    status: &'static str,
    data: &'a T,
}

/// Print one stable, versioned success document to stdout.
pub fn print_success<T: Serialize>(command: &str, data: &T) -> Result<(), serde_json::Error> {
    let envelope = JsonEnvelope {
        schema_version: JSON_SCHEMA_VERSION,
        command,
        status: "ok",
        data,
    };
    println!("{}", serde_json::to_string_pretty(&envelope)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Data {
        value: u32,
    }

    #[test]
    fn success_contract_has_stable_top_level_fields() {
        let value = JsonEnvelope {
            schema_version: JSON_SCHEMA_VERSION,
            command: "inspect",
            status: "ok",
            data: &Data { value: 7 },
        };
        let json = serde_json::to_value(value).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["command"], "inspect");
        assert_eq!(json["status"], "ok");
        assert_eq!(json["data"]["value"], 7);
    }
}
