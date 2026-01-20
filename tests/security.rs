#![allow(missing_docs)]

#[macro_use]
mod common;

#[path = "security/authenticated_tests.rs"]
mod authenticated_tests;
#[path = "security/context_tests.rs"]
mod context_tests;
#[path = "security/integration_tests.rs"]
mod integration_tests;
#[path = "security/key_tests.rs"]
mod key_tests;
#[path = "security/property_tests.rs"]
mod property_tests;
#[path = "security/tag_tests.rs"]
mod tag_tests;
