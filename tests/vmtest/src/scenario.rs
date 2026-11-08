//! Thin raw-syscall test target traced by `fstrace`.
//!
//! A standalone binary whose only job is to perform one gtest-style body of raw
//! syscalls against the shared test directory, so `fstrace` has something to
//! trace. Setup of that directory happens in the client harness *outside*
//! tracing, so this program only issues the traced calls. Deliberately thin:
//! no clap, no error framework — just direct `syscall(2)` invocations (or libc
//! wrappers for legacy calls that ARM64 implements through `*at`), so the
//! traced process adds no incidental filesystem noise.
//!
//! Usage: `fstrace-scenario <name> [args...]`

use std::ffi::CString;

const DIR: &str = "/tmp/fstrace-test-dir";

/// `openat2`'s `struct open_how` (not exposed by the libc crate).
#[repr(C)]
#[derive(Default)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn cs(s: &str) -> CString {
    CString::new(s).expect("scenario paths never contain NUL")
}

/// `path` joined onto the test directory, e.g. `d("/file0")` -> `.../file0`.
fn d(path: &str) -> CString {
    cs(&format!("{DIR}{path}"))
}

macro_rules! sys {
    ($n:expr $(, $a:expr)* $(,)?) => {
        unsafe { libc::syscall($n $(, $a as libc::c_long)*) }
    };
}

fn chdir(path: &CString) {
    sys!(libc::SYS_chdir, path.as_ptr());
}

fn close(fd: libc::c_long) {
    sys!(libc::SYS_close, fd);
}

fn scenario_creat() {
    chdir(&cs(DIR));
    let fd = unsafe { libc::creat(d("/newfile0").as_ptr(), 0o666) } as libc::c_long;
    close(fd);
    let fd = unsafe { libc::creat(cs("./newfile1").as_ptr(), 0o666) } as libc::c_long;
    close(fd);
}

fn scenario_open() {
    chdir(&cs(DIR));
    let fd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        d("/newfile2").as_ptr(),
        libc::O_CREAT,
        0o666
    );
    close(fd);
    let fd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs("./newfile3").as_ptr(),
        libc::O_CREAT,
        0o666
    );
    close(fd);
    let fd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        d("/file0").as_ptr(),
        libc::O_RDONLY
    );
    close(fd);
    let fd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs("./../fstrace-test-dir/./file2").as_ptr(),
        libc::O_RDONLY
    );
    close(fd);
    let fd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        d("/file1").as_ptr(),
        libc::O_RDWR
    );
    close(fd);
}

fn scenario_openat() {
    chdir(&cs(DIR));
    let dirfd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs(DIR).as_ptr(),
        libc::O_RDONLY | libc::O_DIRECTORY
    );
    let fd = sys!(
        libc::SYS_openat,
        dirfd,
        d("/file0").as_ptr(),
        libc::O_RDONLY
    );
    close(fd);
    let fd = sys!(libc::SYS_openat, dirfd, d("/file0").as_ptr(), libc::O_RDWR);
    close(fd);
    sys!(
        libc::SYS_openat,
        dirfd,
        d("/does-not-exist").as_ptr(),
        libc::O_WRONLY
    );
    sys!(
        libc::SYS_openat,
        dirfd,
        d("/does-not-exist").as_ptr(),
        libc::O_RDWR
    );
    sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs("does-not-exist").as_ptr(),
        libc::O_RDONLY
    );
    sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs("does-not-exist").as_ptr(),
        libc::O_RDWR
    );
    let fd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs("dir0/").as_ptr(),
        libc::O_RDONLY
    );
    close(fd);
    let fd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs("dir0/").as_ptr(),
        libc::O_RDWR
    );
    close(fd);
    let fd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs("dir0/").as_ptr(),
        libc::O_RDONLY | libc::O_DIRECTORY
    );
    close(fd);
    let fd = sys!(
        libc::SYS_openat,
        dirfd,
        cs("dir0").as_ptr(),
        libc::O_RDWR | libc::O_DIRECTORY
    );
    close(fd);
    let fd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs("dir0").as_ptr(),
        libc::O_RDWR | libc::O_DIRECTORY
    );
    close(fd);
    close(dirfd);
}

fn openat2(dirfd: libc::c_long, path: &CString, flags: u64) -> libc::c_long {
    let how = OpenHow {
        flags,
        ..Default::default()
    };
    sys!(
        libc::SYS_openat2,
        dirfd,
        path.as_ptr(),
        &how as *const OpenHow,
        std::mem::size_of::<OpenHow>()
    )
}

fn scenario_openat2() {
    chdir(&cs(DIR));
    let dir_flags = (libc::O_RDONLY | libc::O_DIRECTORY) as u64;
    let dirfd = openat2(libc::AT_FDCWD as libc::c_long, &cs(DIR), dir_flags);
    let fd = openat2(dirfd, &d("/file0"), libc::O_RDONLY as u64);
    close(fd);
    let fd = openat2(dirfd, &d("/file0"), libc::O_RDWR as u64);
    close(fd);
    openat2(dirfd, &d("/does-not-exist"), libc::O_WRONLY as u64);
    openat2(
        libc::AT_FDCWD as libc::c_long,
        &cs("does-not-exist"),
        libc::O_RDONLY as u64,
    );
    openat2(
        libc::AT_FDCWD as libc::c_long,
        &cs("does-not-exist"),
        libc::O_RDWR as u64,
    );
    let fd = openat2(
        libc::AT_FDCWD as libc::c_long,
        &cs("dir0/"),
        libc::O_RDONLY as u64,
    );
    close(fd);
    let fd = openat2(
        libc::AT_FDCWD as libc::c_long,
        &cs("dir0/"),
        libc::O_RDWR as u64,
    );
    close(fd);
    let fd = openat2(libc::AT_FDCWD as libc::c_long, &cs("dir0/"), dir_flags);
    close(fd);
    let fd = openat2(
        dirfd,
        &cs("dir0"),
        (libc::O_RDWR | libc::O_DIRECTORY) as u64,
    );
    close(fd);
    let fd = openat2(libc::AT_FDCWD as libc::c_long, &cs("dir0"), dir_flags);
    close(fd);
    close(dirfd);
}

fn scenario_unlink() {
    chdir(&cs(DIR));
    let dirfd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs(DIR).as_ptr(),
        libc::O_RDONLY | libc::O_DIRECTORY
    );
    unsafe {
        libc::unlink(cs("file0").as_ptr());
        libc::unlink(d("/file1").as_ptr());
    }
    sys!(
        libc::SYS_unlinkat,
        libc::AT_FDCWD,
        cs("./../fstrace-test-dir/./file2").as_ptr(),
        0
    );
    sys!(libc::SYS_unlinkat, libc::AT_FDCWD, d("/file3").as_ptr(), 0);
    sys!(libc::SYS_unlinkat, dirfd, cs("file4").as_ptr(), 0);
    sys!(libc::SYS_unlinkat, dirfd, cs("file5").as_ptr(), 0);
    close(dirfd);
}

fn scenario_rmdir() {
    chdir(&cs(DIR));
    unsafe {
        libc::rmdir(cs("dir0/").as_ptr());
        libc::rmdir(cs("dir1").as_ptr());
        libc::rmdir(d("/dir2/").as_ptr());
        libc::rmdir(d("/dir3").as_ptr());
    }
}

fn scenario_rename() {
    chdir(&cs(DIR));
    let dirfd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs(DIR).as_ptr(),
        libc::O_DIRECTORY
    );
    unsafe {
        libc::rename(cs("file0").as_ptr(), cs("./newfile0").as_ptr());
        libc::rename(d("/file1").as_ptr(), d("/newfile1").as_ptr());
    }
    sys!(
        libc::SYS_renameat,
        libc::AT_FDCWD,
        d("/file2").as_ptr(),
        dirfd,
        d("/newfile2").as_ptr()
    );
    sys!(
        libc::SYS_renameat,
        libc::AT_FDCWD,
        cs("file3").as_ptr(),
        dirfd,
        cs("./newfile3").as_ptr()
    );
    sys!(
        libc::SYS_renameat2,
        libc::AT_FDCWD,
        d("/file4").as_ptr(),
        dirfd,
        d("/newfile4").as_ptr(),
        0
    );
    sys!(
        libc::SYS_renameat2,
        libc::AT_FDCWD,
        cs("file5").as_ptr(),
        dirfd,
        cs("./newfile5").as_ptr(),
        0
    );
    close(dirfd);
}

fn scenario_mkdir() {
    chdir(&cs(DIR));
    let dirfd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs(DIR).as_ptr(),
        libc::O_DIRECTORY
    );
    unsafe {
        libc::mkdir(d("/newdir0").as_ptr(), 0o777);
        libc::mkdir(cs("./newdir1/").as_ptr(), 0o777);
        libc::mkdir(cs("./newdir2").as_ptr(), 0o777);
    }
    sys!(
        libc::SYS_mkdirat,
        libc::AT_FDCWD,
        d("/newdir3").as_ptr(),
        0o777
    );
    sys!(
        libc::SYS_mkdirat,
        libc::AT_FDCWD,
        cs("./newdir4/").as_ptr(),
        0o777
    );
    sys!(
        libc::SYS_mkdirat,
        libc::AT_FDCWD,
        cs("./newdir5").as_ptr(),
        0o777
    );
    sys!(libc::SYS_mkdirat, dirfd, d("/newdir6").as_ptr(), 0o777);
    sys!(libc::SYS_mkdirat, dirfd, cs("./newdir7/").as_ptr(), 0o777);
    sys!(libc::SYS_mkdirat, dirfd, cs("./newdir8").as_ptr(), 0o777);
    close(dirfd);
}

fn scenario_symlink() {
    chdir(&cs(DIR));
    let dirfd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs(DIR).as_ptr(),
        libc::O_DIRECTORY
    );
    unsafe {
        libc::symlink(d("/file0").as_ptr(), d("/newlink0").as_ptr());
        libc::symlink(cs("file1").as_ptr(), cs("./newlink1").as_ptr());
        libc::symlink(d("/file2").as_ptr(), cs("./newlink2").as_ptr());
    }
    sys!(
        libc::SYS_symlinkat,
        d("/file3").as_ptr(),
        libc::AT_FDCWD,
        cs("./newlink3").as_ptr()
    );
    sys!(
        libc::SYS_symlinkat,
        d("/file3").as_ptr(),
        libc::AT_FDCWD,
        d("/newlink4").as_ptr()
    );
    sys!(
        libc::SYS_symlinkat,
        d("/file5").as_ptr(),
        dirfd,
        d("/newlink5").as_ptr()
    );
    sys!(
        libc::SYS_symlinkat,
        cs("./file6").as_ptr(),
        dirfd,
        cs("./newlink6").as_ptr()
    );
    close(dirfd);
}

fn scenario_link() {
    chdir(&cs(DIR));
    let dirfd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs(DIR).as_ptr(),
        libc::O_DIRECTORY
    );
    unsafe {
        libc::link(d("/file0").as_ptr(), d("/newfile0").as_ptr());
        libc::link(cs("file1").as_ptr(), cs("./newfile1").as_ptr());
    }
    sys!(
        libc::SYS_linkat,
        libc::AT_FDCWD,
        d("/file2").as_ptr(),
        libc::AT_FDCWD,
        d("/newfile2").as_ptr(),
        0
    );
    sys!(
        libc::SYS_linkat,
        libc::AT_FDCWD,
        cs("file3").as_ptr(),
        libc::AT_FDCWD,
        cs("./newfile3").as_ptr(),
        0
    );
    sys!(
        libc::SYS_linkat,
        dirfd,
        d("/file4").as_ptr(),
        libc::AT_FDCWD,
        d("/newfile4").as_ptr(),
        0
    );
    sys!(
        libc::SYS_linkat,
        dirfd,
        cs("file5").as_ptr(),
        libc::AT_FDCWD,
        cs("./newfile5").as_ptr(),
        0
    );
    sys!(
        libc::SYS_linkat,
        libc::AT_FDCWD,
        d("/file6").as_ptr(),
        dirfd,
        d("/newfile6").as_ptr(),
        0
    );
    sys!(
        libc::SYS_linkat,
        libc::AT_FDCWD,
        cs("./file7").as_ptr(),
        dirfd,
        cs("./newfile7").as_ptr(),
        0
    );
    close(dirfd);
}

fn scenario_truncate() {
    chdir(&cs(DIR));
    sys!(libc::SYS_truncate, d("/file0").as_ptr(), 0);
    sys!(libc::SYS_truncate, cs("file1").as_ptr(), 0);
}

fn scenario_getdents() {
    let mut buf = [0u8; 1024];
    let dirfd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs(DIR).as_ptr(),
        libc::O_RDONLY | libc::O_DIRECTORY
    );
    sys!(libc::SYS_getdents64, dirfd, buf.as_mut_ptr(), buf.len());
    close(dirfd);
    let file0fd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        d("/file0").as_ptr(),
        libc::O_RDONLY
    );
    sys!(libc::SYS_getdents64, file0fd, buf.as_mut_ptr(), buf.len());
    close(file0fd);
}

fn scenario_stat() {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    chdir(&cs(DIR));
    sys!(
        libc::SYS_newfstatat,
        libc::AT_FDCWD,
        d("/file0").as_ptr(),
        st.as_mut_ptr(),
        0
    );
    sys!(
        libc::SYS_newfstatat,
        libc::AT_FDCWD,
        d("/does-not-exist").as_ptr(),
        st.as_mut_ptr(),
        0
    );
}

fn scenario_readlink() {
    let mut buf = [0u8; 4096];
    chdir(&cs(DIR));
    sys!(
        libc::SYS_readlinkat,
        libc::AT_FDCWD,
        d("/file0.link").as_ptr(),
        buf.as_mut_ptr(),
        buf.len()
    );
    sys!(
        libc::SYS_readlinkat,
        libc::AT_FDCWD,
        d("/does-not-exist.link").as_ptr(),
        buf.as_mut_ptr(),
        buf.len()
    );
    sys!(
        libc::SYS_readlinkat,
        libc::AT_FDCWD,
        d("/dir0.link").as_ptr(),
        buf.as_mut_ptr(),
        buf.len()
    );
}

fn scenario_fork() {
    // Two-level fork; each descendant truncates a distinct file. Exercises
    // process-tree following.
    chdir(&cs(DIR));
    let a = unsafe { libc::fork() };
    if a == 0 {
        let b = unsafe { libc::fork() };
        if b == 0 {
            sys!(libc::SYS_truncate, d("/file0").as_ptr(), 0);
            unsafe { libc::_exit(0) };
        }
        sys!(libc::SYS_truncate, d("/file1").as_ptr(), 0);
        sys!(libc::SYS_wait4, b, 0, 0, 0);
        unsafe { libc::_exit(0) };
    }
    sys!(libc::SYS_truncate, d("/file2").as_ptr(), 0);
    sys!(libc::SYS_wait4, a, 0, 0, 0);
}

fn exec_target(syscall: libc::c_long, target: &str) {
    let target = cs(target);
    let scenario = cs("stat");
    let argv = [target.as_ptr(), scenario.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null::<libc::c_char>()];
    let rc = if syscall == libc::SYS_execve {
        sys!(
            libc::SYS_execve,
            target.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr()
        )
    } else {
        sys!(
            libc::SYS_execveat,
            libc::AT_FDCWD,
            target.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            0
        )
    };
    eprintln!(
        "exec syscall failed ({rc}): {}",
        std::io::Error::last_os_error()
    );
}

fn scenario_thread_exec(target: &str) {
    let target = target.to_owned();
    std::thread::spawn(move || exec_target(libc::SYS_execve, &target))
        .join()
        .expect("exec thread panicked");
}

fn scenario_inherited_paths() {
    chdir(&cs(DIR));
    let directory = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs("dir0").as_ptr(),
        libc::O_RDONLY | libc::O_DIRECTORY
    );
    let child = unsafe { libc::fork() } as libc::c_long;
    if child == 0 {
        chdir(&cs("dir1"));
        let fd = sys!(
            libc::SYS_openat,
            libc::AT_FDCWD,
            cs("../file0").as_ptr(),
            libc::O_RDONLY
        );
        assert!(fd >= 0);
        close(fd);
        let fd = sys!(
            libc::SYS_openat,
            directory,
            cs("../file1").as_ptr(),
            libc::O_RDONLY
        );
        assert!(fd >= 0);
        close(fd);
        unsafe {
            libc::_exit(0);
        }
    }
    assert!(child > 0);
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(child as i32, &mut status, 0) },
        child as i32
    );
    assert_eq!(status, 0);
    close(directory);
}

fn scenario_leader_exit() {
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let fd = sys!(
            libc::SYS_openat,
            libc::AT_FDCWD,
            d("/leader-worker").as_ptr(),
            libc::O_CREAT | libc::O_WRONLY,
            0o600
        );
        assert!(fd >= 0);
        close(fd);
    });
    sys!(libc::SYS_exit, 0);
}

fn scenario_empty_shared_files() {
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let child_barrier = barrier.clone();
    let child = std::thread::spawn(move || {
        child_barrier.wait();
        close(7);
        assert_eq!(
            sys!(
                libc::SYS_openat,
                libc::AT_FDCWD,
                d("/dir1").as_ptr(),
                libc::O_DIRECTORY
            ),
            7
        );
        child_barrier.wait();
    });
    // Reserve 4..6 so open returns 7 in both threads.
    for fd in 4..7 {
        assert_eq!(unsafe { libc::dup2(1, fd) }, fd);
    }
    assert_eq!(
        sys!(
            libc::SYS_openat,
            libc::AT_FDCWD,
            d("/dir0").as_ptr(),
            libc::O_DIRECTORY
        ),
        7
    );
    barrier.wait();
    barrier.wait();
    let fd = sys!(
        libc::SYS_openat,
        7,
        cs("shared-file").as_ptr(),
        libc::O_CREAT | libc::O_WRONLY,
        0o600
    );
    assert!(fd >= 0);
    close(fd);
    child.join().unwrap();
}

fn scenario_dup_dirfd() {
    let fd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs(DIR).as_ptr(),
        libc::O_DIRECTORY
    );
    assert!(fd >= 0);
    assert_eq!(unsafe { libc::dup2(fd as i32, 17) }, 17);
    close(fd);
    let opened = sys!(libc::SYS_openat, 17, cs("file0").as_ptr(), libc::O_RDONLY);
    assert!(opened >= 0);
    close(opened);
}

struct CloneFs {
    ready: [i32; 2],
    release: [i32; 2],
    exec: bool,
}

extern "C" fn clone_fs_child(raw: *mut libc::c_void) -> i32 {
    let state = unsafe { &*(raw as *const CloneFs) };
    if state.exec {
        let program = std::env::current_exe().unwrap();
        let program = CString::new(program.as_os_str().as_encoded_bytes()).unwrap();
        let ready = cs(&state.ready[1].to_string());
        let release = cs(&state.release[0].to_string());
        let args = [
            program.as_ptr(),
            c"clone-fs-after-exec".as_ptr(),
            ready.as_ptr(),
            release.as_ptr(),
            std::ptr::null(),
        ];
        unsafe {
            libc::execv(program.as_ptr(), args.as_ptr());
        }
        return 127;
    }
    // A failed exec must also leave cwd sharing intact.
    let missing = cs("/missing-clone-fs-exec");
    let args = [missing.as_ptr(), std::ptr::null()];
    unsafe {
        libc::execv(args[0], args.as_ptr());
    }
    clone_fs_after_exec(state.ready[1], state.release[0]);
    0
}

fn clone_fs_after_exec(ready: i32, release: i32) {
    chdir(&d("/dir0"));
    let mut byte = 1u8;
    assert_eq!(
        unsafe { libc::write(ready, (&byte as *const u8).cast(), 1) },
        1
    );
    assert_eq!(
        unsafe { libc::read(release, (&mut byte as *mut u8).cast(), 1) },
        1
    );
}

fn scenario_clone_fs(mode: &str) {
    chdir(&cs(DIR));
    let mut state = CloneFs {
        ready: [-1; 2],
        release: [-1; 2],
        exec: mode != "failed",
    };
    assert_eq!(unsafe { libc::pipe(state.ready.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { libc::pipe(state.release.as_mut_ptr()) }, 0);
    let mut stack = vec![0u8; 1024 * 1024];
    let child = unsafe {
        libc::clone(
            clone_fs_child,
            stack.as_mut_ptr().add(stack.len()).cast(),
            libc::SIGCHLD | if mode == "fork" { 0 } else { libc::CLONE_FS },
            (&mut state as *mut CloneFs).cast(),
        )
    };
    assert!(child > 0);
    let mut byte = 0u8;
    assert_eq!(
        unsafe { libc::read(state.ready[0], (&mut byte as *mut u8).cast(), 1) },
        1
    );
    assert_eq!(
        std::env::current_dir().unwrap().to_str().unwrap(),
        if mode == "fork" {
            DIR.to_string()
        } else {
            format!("{DIR}/dir0")
        }
    );
    let fd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs("cwd-file").as_ptr(),
        libc::O_CREAT | libc::O_WRONLY,
        0o600
    );
    assert!(fd >= 0);
    close(fd);
    assert_eq!(
        unsafe { libc::write(state.release[1], (&byte as *const u8).cast(), 1) },
        1
    );
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0);
}

fn scenario_failed_thread_exec() {
    for _ in 0..32 {
        std::thread::spawn(|| {
            let missing = cs("/fstrace-nonexistent-executable");
            let argv = [missing.as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null::<libc::c_char>()];
            assert_eq!(
                sys!(
                    libc::SYS_execve,
                    missing.as_ptr(),
                    argv.as_ptr(),
                    envp.as_ptr()
                ),
                -1
            );
        })
        .join()
        .unwrap();
    }
    let fd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        d("/after-thread-churn").as_ptr(),
        libc::O_CREAT | libc::O_WRONLY,
        0o600
    );
    assert!(fd >= 0);
    close(fd);
}

fn scenario_execveat_relative(target: &str) {
    let target = std::path::Path::new(target);
    let directory = cs(target.parent().unwrap().to_str().unwrap());
    let filename = cs(target.file_name().unwrap().to_str().unwrap());
    let dirfd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        directory.as_ptr(),
        libc::O_RDONLY | libc::O_DIRECTORY
    );
    assert!(
        dirfd >= 0,
        "opening exec directory: {}",
        std::io::Error::last_os_error()
    );
    chdir(&cs("/"));
    let scenario = cs("stat");
    let argv = [filename.as_ptr(), scenario.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null::<libc::c_char>()];
    sys!(
        libc::SYS_execveat,
        dirfd,
        filename.as_ptr(),
        argv.as_ptr(),
        envp.as_ptr(),
        0
    );
    panic!(
        "relative execveat failed: {}",
        std::io::Error::last_os_error()
    );
}

/// Stress near-PATH_MAX (4096-byte) pathnames end to end.
///   `longabs` = absolute file inside a very deep directory (~PATH_MAX)
///   `longdir` = that very deep directory (to chdir into)
///   `relf`    = a sibling filename (relative, resolved against the deep cwd)
fn scenario_pathmax(longabs: &str, longdir: &str, relf: &str) {
    let longabs = cs(longabs);
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    let fd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        longabs.as_ptr(),
        libc::O_CREAT | libc::O_WRONLY,
        0o666
    );
    close(fd);
    let fd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        longabs.as_ptr(),
        libc::O_RDONLY
    );
    close(fd);
    sys!(
        libc::SYS_newfstatat,
        libc::AT_FDCWD,
        longabs.as_ptr(),
        st.as_mut_ptr(),
        0
    );
    chdir(&cs(longdir));
    let fd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs(relf).as_ptr(),
        libc::O_RDONLY
    );
    close(fd);
}

/// Dispatches a single scenario by name. `args` are the positional arguments
/// after the scenario name (used only by `pathmax`). Returns a usage/error exit
/// code on bad input.
fn run(name: &str, args: &[String]) -> i32 {
    match name {
        "creat" => scenario_creat(),
        "open" => scenario_open(),
        "openat" => scenario_openat(),
        "openat2" => scenario_openat2(),
        "unlink" => scenario_unlink(),
        "rmdir" => scenario_rmdir(),
        "rename" => scenario_rename(),
        "mkdir" => scenario_mkdir(),
        "symlink" => scenario_symlink(),
        "link" => scenario_link(),
        "truncate" => scenario_truncate(),
        "getdents" => scenario_getdents(),
        "stat" => scenario_stat(),
        "readlink" => scenario_readlink(),
        "fork" => scenario_fork(),
        "execveat" => {
            let [target] = args else {
                eprintln!("execveat needs 1 path arg: <target>");
                return 2;
            };
            exec_target(libc::SYS_execveat, target);
        }
        "execveat-relative" => {
            let [target] = args else {
                eprintln!("execveat-relative needs 1 path arg: <target>");
                return 2;
            };
            scenario_execveat_relative(target);
        }
        "thread-exec" => {
            let [target] = args else {
                eprintln!("thread-exec needs 1 path arg: <target>");
                return 2;
            };
            scenario_thread_exec(target);
        }
        "inherited-paths" => scenario_inherited_paths(),
        "leader-exit" => scenario_leader_exit(),
        "empty-shared-files" => scenario_empty_shared_files(),
        "dup-dirfd" => scenario_dup_dirfd(),
        "inherited-dirfd" => {
            let fd = sys!(libc::SYS_openat, 7, cs("file0").as_ptr(), libc::O_RDONLY);
            assert!(fd >= 0);
            close(fd);
        }
        "clone-fs" => scenario_clone_fs(&args[0]),
        "clone-fs-after-exec" => {
            clone_fs_after_exec(args[0].parse().unwrap(), args[1].parse().unwrap())
        }
        "failed-thread-exec" => scenario_failed_thread_exec(),
        "privileges" => {
            println!(
                "{} {} {}",
                unsafe { libc::getuid() },
                unsafe { libc::geteuid() },
                unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) }
            );
        }
        "pressure" => {
            let mut path = format!("{DIR}/missing/{}", "aaaaaaaaa/".repeat(450));
            path.truncate(4090);
            let path = cs(&path);
            for _ in 0..20000 {
                sys!(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    libc::O_RDONLY
                );
            }
        }
        "register-after-exec" => {
            let [first, second] = args else {
                return 2;
            };
            let token = [
                first.parse::<u64>().unwrap(),
                second.parse::<u64>().unwrap(),
            ];
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                0
            );
            unsafe {
                libc::prctl(0x46535452, token[0], token[1], 0u64, 0u64);
                libc::raise(libc::SIGSTOP);
            }
        }
        "pathmax" => {
            let [longabs, longdir, relf] = args else {
                eprintln!("pathmax needs 3 path args: <longabs> <longdir> <relf>");
                return 2;
            };
            scenario_pathmax(longabs, longdir, relf);
        }
        other => {
            eprintln!("unknown scenario: {other}");
            return 2;
        }
    }
    0
}

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_some_and(|arg| arg == "raw-argv") {
        use std::io::Write;
        for arg in &args[2..] {
            std::io::stdout().write_all(arg.as_encoded_bytes()).unwrap();
        }
        return std::process::ExitCode::SUCCESS;
    }
    let args: Vec<_> = args
        .into_iter()
        .map(|arg| arg.into_string().expect("scenario expects UTF-8"))
        .collect();
    let Some(name) = args.get(1) else {
        eprintln!("usage: fstrace-scenario <name> [args...]");
        return std::process::ExitCode::from(2);
    };
    std::process::ExitCode::from(run(name, &args[2..]) as u8)
}
