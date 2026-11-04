//! Compile generated models and check wire presence, closure, and secret diagnostics.

use std::process::Command;

use openapi_to_rust::{CodeGenerator, GeneratorConfig, SchemaAnalyzer};
use serde_json::json;

#[test]
fn generated_models_preserve_explicit_contracts() -> Result<(), Box<dyn std::error::Error>> {
    let spec = json!({
        "openapi": "3.1.0",
        "info": {"title": "model contracts", "version": "1"},
        "paths": {
            "/credentials": {"post": {
                "operationId": "upload",
                "requestBody": {"required": true, "content": {
                    "application/json": {"schema": {"$ref": "#/components/schemas/Credential"}}
                }},
                "responses": {"204": {"description": "accepted"}}
            }}
        },
        "components": {"schemas": {
            "Credential": {
                "type": "object",
                "additionalProperties": false,
                "required": ["password", "file"],
                "properties": {
                    "password": {"type": "string", "writeOnly": true},
                    "file": {"type": "string", "writeOnly": true},
                    "note": {"type": "string"}
                }
            },
            "Closed": {
                "type": "object", "additionalProperties": false,
                "required": ["reason"],
                "properties": {"reason": {"type": "string"}}
            },
            "Envelope": {
                "type": "object",
                "required": ["revoked_at", "encoded"],
                "properties": {
                    "revoked_at": {"type": ["integer", "null"]},
                    "encoded": {"type": ["string", "null"], "format": "byte"},
                    "optional": {"type": ["string", "null"]}
                }
            }
        }}
    });
    let mut analysis = SchemaAnalyzer::new(spec)?.analyze()?;
    let temp = tempfile::TempDir::new()?;
    let generator = CodeGenerator::new(GeneratorConfig {
        output_dir: temp.path().join("src/generated"),
        enable_async_client: false,
        enable_sse_client: false,
        ..Default::default()
    });
    let result = generator.generate_all(&mut analysis)?;
    generator.write_files(&result)?;
    let dependencies =
        std::fs::read_to_string(temp.path().join("src/generated/REQUIRED_DEPS.toml"))?;
    std::fs::write(
        temp.path().join("Cargo.toml"),
        format!(
            "[package]\nname = \"model-contract-smoke\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n{dependencies}\n[dev-dependencies]\nserde_json = \"1\"\n"
        ),
    )?;
    std::fs::write(
        temp.path().join("src/lib.rs"),
        r#"pub mod generated;
#[cfg(test)]
mod tests {
    use super::generated::{Closed, Credential, Envelope};
    use serde_json::json;

    #[test]
    fn secrets_are_redacted_without_changing_the_wire_body() {
        let input = json!({"password":"password-sentinel","file":"file-sentinel"});
        let value: Credential = serde_json::from_value(input.clone()).unwrap();
        let diagnostic = format!("{value:?}");
        assert!(!diagnostic.contains("password-sentinel"));
        assert!(!diagnostic.contains("file-sentinel"));
        assert_eq!(serde_json::to_value(value).unwrap(), input);
        let builder = Credential::builder("password-sentinel".into(), "file-sentinel".into());
        let diagnostic = format!("{builder:?}");
        assert!(!diagnostic.contains("password-sentinel"));
        assert!(!diagnostic.contains("file-sentinel"));
    }

    #[test]
    fn explicitly_closed_objects_reject_unknown_fields() {
        assert!(serde_json::from_value::<Closed>(json!({"reason":"audit"})).is_ok());
        assert!(serde_json::from_value::<Closed>(json!({"reason":"audit","extra":true})).is_err());
    }

    #[test]
    fn required_nullable_members_distinguish_absence_from_null() {
        let input = json!({"revoked_at":null,"encoded":null});
        let value: Envelope = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(serde_json::to_value(value).unwrap(), input);
        assert!(serde_json::from_value::<Envelope>(json!({"encoded":null})).is_err());
        assert!(serde_json::from_value::<Envelope>(json!({"revoked_at":null})).is_err());
        let input = json!({"revoked_at":42,"encoded":"ZmlsZQ==","optional":null});
        let value: Envelope = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(serde_json::to_value(value).unwrap(), input);
    }
}
"#,
    )?;
    let output = Command::new("cargo")
        .args(["test", "--offline", "--quiet"])
        .current_dir(temp.path())
        .env(
            "CARGO_TARGET_DIR",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/model-contract-smoke"),
        )
        .env("CARGO_BUILD_BUILD_DIR", temp.path().join("cargo-build"))
        .output()?;
    assert!(
        output.status.success(),
        "generated model contracts failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
