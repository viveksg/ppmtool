#![allow(
    clippy::fn_to_numeric_cast,
    clippy::let_and_return,
    clippy::let_unit_value
)]

use std::collections::HashSet;
use std::env;
use std::ffi::CString;
use std::ffi::OsStr;
use std::fs::read as read_file;
use std::io::Error;
use std::io::Read as _;
use std::io::Write as _;
use std::os::unix::ffi::OsStringExt as _;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::str;

use blazesym::helper::read_elf_build_id;
use blazesym::inspect;
use blazesym::inspect::Inspector;
use blazesym::normalize::Normalizer;
use blazesym::symbolize;
use blazesym::symbolize::Reason;
use blazesym::symbolize::Symbolized;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use blazesym::ErrorKind;
use blazesym::Pid;

use libc::kill;
use libc::SIGKILL;

use scopeguard::defer;

use test_log::test;


/// Make sure that we fail symbolization when providing a non-existent source.
#[test]
fn error_on_non_existent_source() {
    let non_existent = Path::new("/does-not-exists");
    let srcs = vec![
        symbolize::Source::from(symbolize::GsymFile::new(non_existent)),
        symbolize::Source::Elf(symbolize::Elf::new(non_existent)),
    ];
    let symbolizer = Symbolizer::default();

    for src in srcs {
        let err = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(0x2000100))
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }
}

/// Check that we can symbolize an address using ELF, DWARF, and GSYM.
#[test]
fn symbolize_elf_dwarf_gsym() {
    fn test(src: symbolize::Source, has_code_info: bool) {
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(0x2000100))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "factorial");
        assert_eq!(result.addr, 0x2000100);
        assert_eq!(result.offset, 0);

        if has_code_info {
            let code_info = result.code_info.as_ref().unwrap();
            assert_ne!(code_info.dir, None);
            assert_eq!(code_info.file, OsStr::new("test-stable-addresses.c"));
            assert_eq!(code_info.line, Some(8));
        } else {
            assert_eq!(result.code_info, None);
        }

        let size = result.size.unwrap();
        assert_ne!(size, 0);

        // Now check that we can symbolize addresses at a positive offset from the
        // start of the function.
        let offsets = (1..size).collect::<Vec<_>>();
        let addrs = offsets
            .iter()
            .map(|offset| (0x2000100 + offset) as Addr)
            .collect::<Vec<_>>();
        let results = symbolizer
            .symbolize(&src, symbolize::Input::VirtOffset(&addrs))
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), addrs.len());

        for (i, symbolized) in results.into_iter().enumerate() {
            let result = symbolized.into_sym().unwrap();
            assert_eq!(result.name, "factorial");
            assert_eq!(result.addr, 0x2000100);
            assert_eq!(result.offset, offsets[i]);

            if has_code_info {
                let code_info = result.code_info.as_ref().unwrap();
                assert_ne!(code_info.dir, None);
                assert_eq!(code_info.file, OsStr::new("test-stable-addresses.c"));
                assert!(code_info.line.is_some());
            } else {
                assert_eq!(result.code_info, None);
            }
        }
    }

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-no-dwarf.bin");
    let src = symbolize::Source::Elf(symbolize::Elf::new(path));
    test(src, false);

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-dwarf-only.bin");
    let src = symbolize::Source::Elf(symbolize::Elf::new(path));
    test(src, true);

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses.gsym");
    let src = symbolize::Source::from(symbolize::GsymFile::new(&path));
    test(src, true);

    let data = read_file(&path).unwrap();
    let src = symbolize::Source::from(symbolize::GsymData::new(&data));
    test(src, true);
}

/// Check that we "fail" symbolization as expected on a stripped ELF
/// binary.
#[test]
fn symbolize_elf_stripped() {
    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-stripped.bin");
    let src = symbolize::Source::Elf(symbolize::Elf::new(path));
    let symbolizer = Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(0x2000100))
        .unwrap();

    assert_eq!(result, Symbolized::Unknown(Reason::MissingSyms));
}

/// Make sure that we report (enabled) or don't report (disabled) inlined
/// functions with DWARF and Gsym sources.
#[test]
fn symbolize_dwarf_gsym_inlined() {
    fn test(src: symbolize::Source, inlined_fns: bool) {
        let symbolizer = Symbolizer::builder()
            .enable_inlined_fns(inlined_fns)
            .build();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(0x200020a))
            .unwrap()
            .into_sym()
            .unwrap();

        let code_info = result.code_info.as_ref().unwrap();
        assert_ne!(code_info.dir, None);
        assert_eq!(code_info.file, OsStr::new("test-stable-addresses.c"));
        // The Gsym format uses inline information to "refine" the
        // line information associated with an address. As a result,
        // when we ignore inline information we may end up with a
        // slightly misleading location, namely that of the deepest
        // inlined caller.
        assert_eq!(code_info.line, Some(if inlined_fns { 32 } else { 21 }));

        if inlined_fns {
            assert_eq!(result.inlined.len(), 2);

            let name = &result.inlined[0].name;
            assert_eq!(*name, "factorial_inline_wrapper");
            let frame = result.inlined[0].code_info.as_ref().unwrap();
            assert_eq!(frame.file, OsStr::new("test-stable-addresses.c"));
            assert_eq!(frame.line, Some(26));

            let name = &result.inlined[1].name;
            assert_eq!(*name, "factorial_2nd_layer_inline_wrapper");
            let frame = result.inlined[1].code_info.as_ref().unwrap();
            assert_eq!(frame.file, OsStr::new("test-stable-addresses.c"));
            assert_eq!(frame.line, Some(21));
        } else {
            assert!(result.inlined.is_empty(), "{:#?}", result.inlined);
        }
    }

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses.gsym");
    let src = symbolize::Source::from(symbolize::GsymFile::new(path));
    test(src.clone(), true);
    test(src, false);

    let path = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-dwarf-only.bin");
    let src = symbolize::Source::from(symbolize::Elf::new(path));
    test(src.clone(), true);
    test(src, false);
}

/// Check that we can symbolize the `abort_creds` function inside a
/// kernel image properly. Inside of
/// vmlinux-5.17.12-100.fc34.x86_64.dwarf, this function's address range
/// and name are in separate attributes:
/// ```text
/// 0x01273e11: DW_TAG_subprogram
///               DW_AT_abstract_origin     (0x0126ff5d "abort_creds")
///               DW_AT_low_pc      (0xffffffff8110ecb0)
///               DW_AT_high_pc     (0xffffffff8110ecce)
///               DW_AT_frame_base  (DW_OP_call_frame_cfa)
///               DW_AT_call_all_calls      (true)
///               DW_AT_sibling     (0x01273f66)
///
/// 0x0110932c: DW_TAG_subprogram
///               DW_AT_external    (true)
///               DW_AT_name        ("abort_creds")
///               DW_AT_decl_file   ("<...>/include/linux/cred.h")
///               DW_AT_decl_line   (163)
///               DW_AT_decl_column (0x0d)
///               DW_AT_prototyped  (true)
///               DW_AT_declaration (true)
///               DW_AT_sibling     (0x0110933e)
/// ```
/// In the past we were unable to handle this case properly.
#[test]
#[cfg_attr(not(feature = "generate-large-test-files"), ignore)]
fn symbolize_dwarf_complex() {
    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("vmlinux-5.17.12-100.fc34.x86_64.dwarf");
    let src = symbolize::Source::Elf(symbolize::Elf::new(test_dwarf));
    let symbolizer = Symbolizer::new();
    let result = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(0xffffffff8110ecb0))
        .unwrap()
        .into_sym()
        .unwrap();

    assert_eq!(result.name, "abort_creds");
    assert_eq!(result.addr, 0xffffffff8110ecb0);
    assert_eq!(result.code_info.as_ref().unwrap().line, Some(534));
}


/// Symbolize an address inside a DWARF file, with and without auto-demangling
/// enabled.
#[test]
fn symbolize_dwarf_demangle() {
    fn test(test_dwarf: &Path, addr: Addr) -> Result<(), ()> {
        let src = symbolize::Source::Elf(symbolize::Elf::new(test_dwarf));
        let symbolizer = Symbolizer::builder().enable_demangling(false).build();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(addr))
            .unwrap()
            .into_sym()
            .unwrap();

        assert!(
            result.name.contains("test13test_function"),
            "{}",
            result.name
        );

        if result.inlined.is_empty() {
            return Err(())
        }
        assert!(
            result.inlined[0].name.contains("test12inlined_call"),
            "{}",
            result.inlined[0].name
        );

        // Do it again, this time with demangling enabled.
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(addr))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "test::test_function");
        assert_eq!(result.inlined.len(), 1, "{:#?}", result.inlined);
        assert_eq!(result.inlined[0].name, "test::inlined_call");
        Ok(())
    }

    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-rs.bin");
    let elf = inspect::Elf::new(&test_dwarf);
    let src = inspect::Source::Elf(elf);

    let inspector = Inspector::new();
    let results = inspector
        .lookup(&src, &["_RNvCs69hjMPjVIJK_4test13test_function"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert!(!results.is_empty());

    let addr = results[0].addr;
    let src = symbolize::Source::Elf(symbolize::Elf::new(&test_dwarf));
    let symbolizer = Symbolizer::builder().enable_demangling(false).build();
    let result = symbolizer
        .symbolize_single(&src, symbolize::Input::VirtOffset(addr))
        .unwrap()
        .into_sym()
        .unwrap();

    let addr = result.addr;
    let size = result.size.unwrap() as u64;
    for inst_addr in addr..addr + size {
        if test(&test_dwarf, inst_addr).is_ok() {
            return
        }
    }

    panic!("failed to find inlined function call");
}

/// Check that we can symbolize addresses inside our own process.
#[test]
fn symbolize_process() {
    let src = symbolize::Source::Process(symbolize::Process::new(Pid::Slf));
    let addrs = [symbolize_process as Addr, Symbolizer::symbolize as Addr];
    let symbolizer = Symbolizer::new();
    let results = symbolizer
        .symbolize(&src, symbolize::Input::AbsAddr(&addrs))
        .unwrap()
        .into_iter()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 2);

    let result = results[0].as_sym().unwrap();
    assert!(result.name.contains("symbolize_process"), "{result:x?}");

    let result = results[1].as_sym().unwrap();
    // It's not entirely clear why we have seen two different demangled
    // symbols, but they both seem legit.
    assert!(
        result.name == "blazesym::symbolize::symbolizer::Symbolizer::symbolize"
            || result.name == "<blazesym::symbolize::symbolizer::Symbolizer>::symbolize",
        "{}",
        result.name
    );
}

/// Check that we can symbolize an address in a process using a binary
/// located in a local mount namespace.
#[test]
fn symbolize_process_in_mount_namespace() {
    let test_so = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("libtest-so.so");
    let mnt_ns = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-mnt-ns.bin");

    let mut child = Command::new(mnt_ns)
        .arg(test_so)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let pid = child.id();
    defer!({
        // Best effort only. The child may end up terminating gracefully
        // if everything goes as planned.
        // TODO: Ideally this kill would be pid FD based to eliminate
        //       any possibility of killing the wrong entity.
        let _rc = unsafe { kill(pid as _, SIGKILL) };
    });

    let mut buf = [0u8; 64];
    let count = child
        .stdout
        .as_mut()
        .unwrap()
        .read(&mut buf)
        .expect("failed to read child output");
    let addr_str = str::from_utf8(&buf[0..count]).unwrap().trim_end();
    let addr = Addr::from_str_radix(addr_str.trim_start_matches("0x"), 16).unwrap();

    // Make sure to destroy the symbolizer before terminating the child.
    // Otherwise something holds on to a reference and cleanup may fail.
    // TODO: This needs to be better understood.
    {
        let src = symbolize::Source::Process(symbolize::Process::new(Pid::from(child.id())));
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::AbsAddr(addr))
            .unwrap()
            .into_sym()
            .unwrap();
        assert_eq!(result.name, "await_input");
    }

    // "Signal" the child to terminate gracefully.
    let () = child.stdin.as_ref().unwrap().write_all(&[0x04]).unwrap();
    let _status = child.wait().unwrap();
}

/// Check that we can normalize addresses in an ELF shared object.
#[test]
fn normalize_elf_addr() {
    fn test(so: &str) {
        let test_so = Path::new(&env!("CARGO_MANIFEST_DIR")).join("data").join(so);
        let so_cstr = CString::new(test_so.clone().into_os_string().into_vec()).unwrap();
        let handle = unsafe { libc::dlopen(so_cstr.as_ptr(), libc::RTLD_NOW) };
        assert!(!handle.is_null());

        let the_answer_addr = unsafe { libc::dlsym(handle, "the_answer\0".as_ptr().cast()) };
        assert!(!the_answer_addr.is_null());

        let normalizer = Normalizer::new();
        let normalized = normalizer
            .normalize_user_addrs_sorted(Pid::Slf, [the_answer_addr as Addr].as_slice())
            .unwrap();
        assert_eq!(normalized.outputs.len(), 1);
        assert_eq!(normalized.meta.len(), 1);

        let rc = unsafe { libc::dlclose(handle) };
        assert_eq!(rc, 0, "{}", Error::last_os_error());

        let output = normalized.outputs[0];
        let meta = &normalized.meta[output.1];
        assert_eq!(meta.elf().unwrap().path, test_so);

        let elf = symbolize::Elf::new(test_so);
        let src = symbolize::Source::Elf(elf);
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::FileOffset(output.0))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "the_answer");

        let results = symbolizer
            .symbolize(&src, symbolize::Input::FileOffset(&[output.0]))
            .unwrap();
        assert_eq!(results.len(), 1);

        let sym = results[0].as_sym().unwrap();
        assert_eq!(sym.name, "the_answer");
    }

    test("libtest-so.so");
    test("libtest-so-no-separate-code.so");
}


/// Check that we can enable/disable the reading of build IDs.
#[test]
fn normalize_build_id_rading() {
    fn test(read_build_ids: bool) {
        let test_so = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("libtest-so.so");
        let so_cstr = CString::new(test_so.clone().into_os_string().into_vec()).unwrap();
        let handle = unsafe { libc::dlopen(so_cstr.as_ptr(), libc::RTLD_NOW) };
        assert!(!handle.is_null());

        let the_answer_addr = unsafe { libc::dlsym(handle, "the_answer\0".as_ptr().cast()) };
        assert!(!the_answer_addr.is_null());

        let normalizer = Normalizer::builder()
            .enable_build_ids(read_build_ids)
            .build();
        let normalized = normalizer
            .normalize_user_addrs_sorted(Pid::Slf, [the_answer_addr as Addr].as_slice())
            .unwrap();
        assert_eq!(normalized.outputs.len(), 1);
        assert_eq!(normalized.meta.len(), 1);

        let rc = unsafe { libc::dlclose(handle) };
        assert_eq!(rc, 0, "{}", Error::last_os_error());

        let output = normalized.outputs[0];
        let meta = &normalized.meta[output.1];
        let elf = meta.elf().unwrap();
        assert_eq!(elf.path, test_so);
        if read_build_ids {
            let expected = read_elf_build_id(&test_so).unwrap().unwrap();
            assert_eq!(elf.build_id.as_deref().unwrap(), &expected);
        } else {
            assert_eq!(elf.build_id, None);
        }
    }

    test(true);
    test(false);
}


/// Check that we can look up an address.
#[test]
fn inspect() {
    fn test(src: inspect::Source) {
        let inspector = Inspector::new();
        let results = inspector
            .lookup(&src, &["factorial"])
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 1);

        let result = &results[0];
        assert_eq!(result.addr, 0x2000100);
        assert_ne!(result.file_offset, None);
        assert_eq!(
            result.obj_file_name.as_deref().unwrap(),
            src.path().unwrap()
        );
    }

    let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-dwarf-only.bin");
    let src = inspect::Source::Elf(inspect::Elf::new(test_dwarf));
    let () = test(src);

    let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-no-dwarf.bin");
    let mut elf = inspect::Elf::new(test_elf);
    assert!(elf.debug_syms);
    elf.debug_syms = false;
    let src = inspect::Source::Elf(elf);
    let () = test(src);
}


/// Make sure that we can look up a dynamic symbol in an ELF file.
#[test]
fn inspect_dynamic_symbol() {
    #[track_caller]
    fn test(bin: &str) {
        let bin = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join(bin);

        let src = inspect::Source::Elf(inspect::Elf::new(&bin));
        let inspector = Inspector::new();
        let results = inspector
            .lookup(&src, &["the_answer"])
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 1);

        let src = symbolize::Source::Elf(symbolize::Elf::new(&bin));
        let symbolizer = Symbolizer::new();
        let result = symbolizer
            .symbolize_single(&src, symbolize::Input::VirtOffset(results[0].addr))
            .unwrap()
            .into_sym()
            .unwrap();

        assert_eq!(result.name, "the_answer");
        assert_eq!(result.addr, results[0].addr);
    }

    test("libtest-so.so");
    test("libtest-so-stripped.so");
    test("libtest-so-partly-stripped.so");
}


/// Read four bytes at the given `offset` in the file identified by `path`.
fn read_4bytes_at(path: &Path, offset: u64) -> [u8; 4] {
    let offset = offset as usize;
    let content = read_file(path).unwrap();
    let slice = &content[offset..offset + 4];
    <[u8; 4]>::try_from(slice).unwrap()
}


/// Check that we can correctly retrieve the file offset in an ELF file.
#[test]
fn inspect_file_offset_elf() {
    let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-no-dwarf.bin");
    let elf = inspect::Elf::new(test_elf);
    let src = inspect::Source::Elf(elf);

    let inspector = Inspector::new();
    let results = inspector
        .lookup(&src, &["dummy"])
        .unwrap()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 1);

    let result = &results[0];
    assert_ne!(result.file_offset, None);
    let bytes = read_4bytes_at(src.path().unwrap(), result.file_offset.unwrap());
    assert_eq!(bytes, [0xde, 0xad, 0xbe, 0xef]);
}


/// Check that we can iterate over all symbols in an ELF file.
#[test]
fn inspect_all_symbols() {
    let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("test-stable-addresses-no-dwarf.bin");
    let elf = inspect::Elf::new(test_elf);
    let src = inspect::Source::Elf(elf);

    let inspector = Inspector::new();
    let syms = inspector
        .for_each(&src, HashSet::<String>::new(), |mut syms, sym| {
            let _inserted = syms.insert(sym.name.to_string());
            syms
        })
        .unwrap();

    assert!(syms.contains("main"));
    assert!(syms.contains("factorial"));
    assert!(syms.contains("factorial_wrapper"));
    assert!(syms.contains("factorial_inline_test"));
}


/// Check that we can iterate over all symbols in an ELF file, without
/// encountering duplicates caused by dynamic/static symbol overlap.
#[test]
fn inspect_all_symbols_without_duplicates() {
    let test_elf = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("libtest-so.so");
    let elf = inspect::Elf::new(test_elf);
    let src = inspect::Source::Elf(elf);

    let inspector = Inspector::new();
    let syms = inspector
        .for_each(&src, Vec::<String>::new(), |mut syms, sym| {
            let () = syms.push(sym.name.to_string());
            syms
        })
        .unwrap();

    assert_eq!(syms.iter().filter(|name| *name == "the_answer").count(), 1);
}
