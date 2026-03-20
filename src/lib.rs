//! Zero-Trust Admission Controller library
//!
//! Exposes policy and validator modules for testing

pub mod policy;
pub mod validator;

pub use policy::PolicyConfig;
pub use validator::validate_pod;
