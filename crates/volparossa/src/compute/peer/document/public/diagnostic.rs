//! Closed local observations only, never a raw error, prompt, key, path or receipt.

use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};

use super::super::super::rpc_diagnostic;
use super::super::Phase;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ErrorClass {
    #[default]
    None,
    IoNotFound,
    IoPermission,
    IoOther,
    JsonSyntax,
    JsonData,
    JsonEof,
    JsonIo,
    ReapedWorker,
    PeerRpc,
    InvariantOrUnknown,
}

pub(super) fn classify(error: &anyhow::Error) -> ErrorClass {
    if rpc_diagnostic(error).is_some() {
        ErrorClass::PeerRpc
    } else if error
        .downcast_ref::<crate::compute::supervise::WorkerFailure>()
        .is_some()
    {
        ErrorClass::ReapedWorker
    } else if let Some(error) = error.downcast_ref::<std::io::Error>() {
        match error.kind() {
            std::io::ErrorKind::NotFound => ErrorClass::IoNotFound,
            std::io::ErrorKind::PermissionDenied => ErrorClass::IoPermission,
            _ => ErrorClass::IoOther,
        }
    } else if let Some(error) = error.downcast_ref::<serde_json::Error>() {
        match error.classify() {
            serde_json::error::Category::Io => ErrorClass::JsonIo,
            serde_json::error::Category::Syntax => ErrorClass::JsonSyntax,
            serde_json::error::Category::Data => ErrorClass::JsonData,
            serde_json::error::Category::Eof => ErrorClass::JsonEof,
        }
    } else {
        ErrorClass::InvariantOrUnknown
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReceiptPhase {
    #[default]
    ScanTree,
    ReadHandle,
    DecodeHandle,
    DuplicateHandle,
    ReadReceipt,
    DecodeReceipt,
    HandleLookup,
    Binding,
    StatusValidation,
    MissingTerminal,
    Complete,
}

#[derive(Default, Serialize)]
pub(super) struct ReceiptObservation {
    pub phase: ReceiptPhase,
    pub handles: usize,
    pub receipts: usize,
    pub terminal: usize,
    pub error: ErrorClass,
    pub confirmed: bool,
}

pub(super) fn report(
    phase: Phase,
    result: &Result<Value>,
    local_cleanup: bool,
    receipts: &ReceiptObservation,
    cleanup_confirmed: bool,
) -> Value {
    let error = result.as_ref().err();
    json!({"version":1,"phase":phase,"execution_ok":result.is_ok(),
        "error_class":error.map_or(ErrorClass::None, classify),
        "rpc":error.and_then(rpc_diagnostic),
        "local_cleanup_confirmed":local_cleanup,"receipts":receipts,
        "cleanup_confirmed":cleanup_confirmed})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_classifies_types_without_exporting_their_text() {
        let secret = "PRIVATE_PROMPT /private/path key=not-for-export";
        for error in [
            anyhow::anyhow!(secret),
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, secret).into(),
            serde_json::from_str::<Value>("\"PRIVATE_PROMPT")
                .unwrap_err()
                .into(),
        ] {
            let value = report(
                Phase::Tokenization,
                &Err(error),
                false,
                &ReceiptObservation::default(),
                false,
            );
            let encoded = value.to_string();
            assert!(!encoded.contains("PRIVATE_PROMPT"));
            assert!(!encoded.contains("/private/path"));
            assert_eq!(value["phase"], "tokenization");
            assert_eq!(value["cleanup_confirmed"], false);
        }
        assert_eq!(
            classify(&std::io::Error::from(std::io::ErrorKind::NotFound).into()),
            ErrorClass::IoNotFound
        );
    }
}
