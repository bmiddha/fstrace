//! Thin raw-syscall test target traced by `fstrace`.
//!
//! A standalone binary whose only job is to perform one gtest-style body of raw
//! syscalls against the shared test directory, so `fstrace` has something to
//! trace. Setup of that directory happens in the client harness *outside*
//! tracing, so this program only issues the traced calls. Deliberately thin:
//! no clap, no error framework — just direct `syscall(2)` invocations, so the
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
    let fd = sys!(libc::SYS_creat, d("/newfile0").as_ptr(), 0o666);
    close(fd);
    let fd = sys!(libc::SYS_creat, cs("./newfile1").as_ptr(), 0o666);
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
    sys!(libc::SYS_unlink, cs("file0").as_ptr());
    sys!(libc::SYS_unlink, d("/file1").as_ptr());
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
    sys!(libc::SYS_rmdir, cs("dir0/").as_ptr());
    sys!(libc::SYS_rmdir, cs("dir1").as_ptr());
    sys!(libc::SYS_rmdir, d("/dir2/").as_ptr());
    sys!(libc::SYS_rmdir, d("/dir3").as_ptr());
}

fn scenario_rename() {
    chdir(&cs(DIR));
    let dirfd = sys!(
        libc::SYS_openat,
        libc::AT_FDCWD,
        cs(DIR).as_ptr(),
        libc::O_DIRECTORY
    );
    sys!(
        libc::SYS_rename,
        cs("file0").as_ptr(),
        cs("./newfile0").as_ptr()
    );
    sys!(
        libc::SYS_rename,
        d("/file1").as_ptr(),
        d("/newfile1").as_ptr()
    );
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
    sys!(libc::SYS_mkdir, d("/newdir0").as_ptr(), 0o777);
    sys!(libc::SYS_mkdir, cs("./newdir1/").as_ptr(), 0o777);
    sys!(libc::SYS_mkdir, cs("./newdir2").as_ptr(), 0o777);
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
    sys!(
        libc::SYS_symlink,
        d("/file0").as_ptr(),
        d("/newlink0").as_ptr()
    );
    sys!(
        libc::SYS_symlink,
        cs("file1").as_ptr(),
        cs("./newlink1").as_ptr()
    );
    sys!(
        libc::SYS_symlink,
        d("/file2").as_ptr(),
        cs("./newlink2").as_ptr()
    );
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
    sys!(
        libc::SYS_link,
        d("/file0").as_ptr(),
        d("/newfile0").as_ptr()
    );
    sys!(
        libc::SYS_link,
        cs("file1").as_ptr(),
        cs("./newfile1").as_ptr()
    );
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
        "thread-exec" => {
            let [target] = args else {
                eprintln!("thread-exec needs 1 path arg: <target>");
                return 2;
            };
            scenario_thread_exec(target);
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
    let args: Vec<String> = std::env::args().collect();
    let Some(name) = args.get(1) else {
        eprintln!("usage: fstrace-scenario <name> [args...]");
        return std::process::ExitCode::from(2);
    };
    std::process::ExitCode::from(run(name, &args[2..]) as u8)
}
