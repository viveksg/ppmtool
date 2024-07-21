#![allow(
    clippy::fn_to_numeric_cast,
    clippy::let_and_return,
    clippy::let_unit_value
)]

use std::fs::copy;
use std::fs::metadata;
use std::fs::set_permissions;
use std::io::Error;
use std::os::unix::fs::PermissionsExt as _;
use std::panic::catch_unwind;
use std::panic::UnwindSafe;
use std::path::Path;

use blazesym::symbolize;
use blazesym::symbolize::Symbolizer;
use blazesym::ErrorKind;

use libc::getresuid;
use libc::seteuid;
use libc::uid_t;

use tempfile::NamedTempFile;

use test_log::test;


const NOBODY: uid_t = 65534;


/// Run a function with a different effective user ID.
fn as_user<F, R>(ruid: uid_t, euid: uid_t, f: F) -> R
where
    F: FnOnce() -> R + UnwindSafe,
{
    if unsafe { seteuid(euid) } == -1 {
        panic!(
            "failed to set effective user ID to {euid}: {}",
            Error::last_os_error()
        )
    }

    let result = catch_unwind(f);

    // Make sure that we restore the real user before tearing down,
    // because shut down code may need the original permissions (e.g., for
    // writing down code coverage files or similar.
    if unsafe { seteuid(ruid) } == -1 {
        panic!(
            "failed to restore effective user ID to {ruid}: {}",
            Error::last_os_error()
        )
    }

    result.unwrap()
}


fn symbolize_no_permission_impl(path: &Path) {
    let src = symbolize::Source::Elf(symbolize::Elf::new(path));
    let symbolizer = Symbolizer::new();
    let err = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(0x2000100))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
}


/// Check that we fail symbolization as expected when we don't have the
/// permission to open the symbolization source.
#[test]
// This test relies on a nobody user with UID 65534 being present, which
// is not guaranteed. The cfg_attr dance is necessary because the
// bencher benchmarking infrastructure doesn't work properly with the
// --include-ignored argument, at least not when invoked via
// cargo-llvm-cov.
#[cfg_attr(
    not(feature = "nightly"),
    ignore = "test assumes nobody user with UID 65534"
)]
fn symbolize_no_permission() {
    // We run as root. Even if we limit permissions for a root-owned file we can
    // still access it (unlike the behavior for regular users). As such, we have
    // to work as a different user to check handling of permission denied
    // errors. Because such a change is process-wide, though, we can't do that
    // directly but have to fork first.
    let mut ruid = 0;
    let mut euid = 0;
    let mut suid = 0;

    let result = unsafe { getresuid(&mut ruid, &mut euid, &mut suid) };
    if result == -1 {
        panic!("failed to get user IDs: {}", Error::last_os_error());
    }

    let src = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-no-dwarf.bin");

    let tmpfile = NamedTempFile::new().unwrap();
    let path = tmpfile.path();
    let _bytes = copy(src, path).unwrap();

    let mut permissions = metadata(path).unwrap().permissions();
    // Clear all permissions.
    let () = permissions.set_mode(0o0);
    let () = set_permissions(path, permissions).unwrap();

    as_user(ruid, NOBODY, || symbolize_no_permission_impl(path))
}
