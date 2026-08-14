// Standalone semantic replay of axum PR 3848's opaque filename rejection.

fn before_filename(value: &[u8]) -> Option<Vec<u8>> {
    Some(value.to_vec())
}

fn after_filename(value: &[u8]) -> Option<Vec<u8>> {
    std::str::from_utf8(value).ok().map(|_| value.to_vec())
}

fn main() {
    let opaque = b"report\xff.pdf";
    let before_defect_observed = before_filename(opaque).is_some();
    let after_rejects_opaque = after_filename(opaque).is_none();
    let after_accepts_text = after_filename(b"report.pdf").is_some();
    assert!(before_defect_observed);
    assert!(after_rejects_opaque);
    assert!(after_accepts_text);
    println!(
        "{{\"after_expectation_passed\":true,\"before_defect_observed\":true,\"case_id\":\"axum-3848\",\"language\":\"Rust\",\"scope\":\"standalone semantic micro-replay; not the axum test suite\"}}"
    );
}
