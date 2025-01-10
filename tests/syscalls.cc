#include <gtest/gtest.h>

#include <string>
#include <cstdio>
#include <memory>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include "src/trace_exec.cc"

bool SubstringCountPredicate(const std::string &str, const std::string &substr, int expected_count)
{
  int count = 0;
  size_t pos = str.find(substr);
  while (pos != std::string::npos)
  {
    ++count;
    pos = str.find(substr, pos + substr.length());
  }
  return count == expected_count;
}

template <typename... Args> std::string trace_testfn(void (*testfn)(Args...), Args... args)
{
  int pipefd[2];
  if (pipe(pipefd) == -1)
  {
    throw std::runtime_error("pipe() failed!");
  }

  // this is a modified version of trace_exec() which instead skips running execve()
  // run tracer and forward fd3 to the pipe, so that we can verify the output
  pid_t tracer_pid = fork();
  if (tracer_pid == 0)
  {
    syscall(__NR_close, pipefd[0]);
    dup2(pipefd[1], 3);
    syscall(__NR_close, pipefd[1]);

    pid_t tracee_pid = fork();
    if (tracee_pid == 0)
    {
      if (prepare_tracee() != 0)
      {
        std::runtime_error("prepare_tracee() failed!");
      }
      testfn(args...);
    }
    else
    {
      if (run_tracer(tracee_pid) != 0)
      {
        std::runtime_error("run_tracer() failed!");
      }
    }
  }
  else
  {
    std::array<char, 128> buffer;
    std::string result;
    syscall(__NR_close, pipefd[1]);

    ssize_t bytes_read;
    while ((bytes_read = read(pipefd[0], buffer.data(), buffer.size())) > 0)
    {
      result.append(buffer.data(), bytes_read);
    }
    syscall(__NR_close, pipefd[0]);

    int status;
    waitpid(tracer_pid, &status, 0);
    return result;
  }

  return "";
}

char *path_dir0 = "/tmp/fstrace-test-dir/dir0";
char *path_dir0_link = "/tmp/fstrace-test-dir/dir0.link";
char *path_dir0_link_rel = "./dir0.link";
char *path_dir0_rel = "./dir0";
char *path_dir0_trailing_slash = "/tmp/fstrace-test-dir/dir0/";
char *path_dir0_trailing_slash_rel = "./dir0/";
char *path_dir1 = "/tmp/fstrace-test-dir/dir1";
char *path_dir1_rel = "./dir1";
char *path_dir1_trailing_slash = "/tmp/fstrace-test-dir/dir1/";
char *path_dir1_trailing_slash_rel = "./dir1/";
char *path_dir10_trailing_slash = "/tmp/fstrace-test-dir/dir10/";
char *path_dir11 = "/tmp/fstrace-test-dir/dir11";
char *path_dir2 = "/tmp/fstrace-test-dir/dir2";
char *path_dir2_rel = "./dir2";
char *path_dir2_trailing_slash = "/tmp/fstrace-test-dir/dir2/";
char *path_dir3 = "/tmp/fstrace-test-dir/dir3";
char *path_dir3_trailing_slash = "/tmp/fstrace-test-dir/dir3/";
char *path_dir4_trailing_slash_rel = "./dir4/";
char *path_dir5_rel = "./dir5";
char *path_dir6_trailing_slash = "/tmp/fstrace-test-dir/dir6/";
char *path_dir7 = "/tmp/fstrace-test-dir/dir7";
char *path_dir8_trailing_slash_rel = "./dir8/";
char *path_dir9_rel = "./dir9";
char *path_doesnotexist = "/tmp/fstrace-test-dir/does-not-exist";
char *path_doesnotexist_link = "/tmp/fstrace-test-dir/does-not-exist.link";
char *path_doesnotexist_link_rel = "./does-not-exist.link";
char *path_doesnotexist_rel = "./does-not-exist";
char *path_file_5 = "/tmp/fstrace-test-dir/file5";
char *path_file0 = "/tmp/fstrace-test-dir/file0";
char *path_file0_link = "/tmp/fstrace-test-dir/file0.link";
char *path_file0_link_rel = "./file0.link";
char *path_file0_rel = "./file0";
char *path_file1 = "/tmp/fstrace-test-dir/file1";
char *path_file1_rel = "./file1";
char *path_file2 = "/tmp/fstrace-test-dir/file2";
char *path_file2_rel_irregular = "./../fstrace-test-dir/./file2";
char *path_file3 = "/tmp/fstrace-test-dir/file3";
char *path_file3_rel = "./file3";
char *path_file4 = "/tmp/fstrace-test-dir/file4";
char *path_file4_rel = "./file4";
char *path_file5 = "/tmp/fstrace-test-dir/file5";
char *path_file5_rel = "./file5";
char *path_file6 = "/tmp/fstrace-test-dir/file6";
char *path_file7 = "/tmp/fstrace-test-dir/file7";
char *path_file6_rel = "./file6";
char *path_file7_rel = "./file7";
char *path_newfile0 = "/tmp/fstrace-test-dir/newfile0";
char *path_newfile0_rel = "./newfile0";
char *path_newfile1 = "/tmp/fstrace-test-dir/newfile1";
char *path_newfile1_rel = "./newfile1";
char *path_newfile2 = "/tmp/fstrace-test-dir/newfile2";
char *path_newfile3_rel = "./newfile3";
char *path_newfile4 = "/tmp/fstrace-test-dir/newfile4";
char *path_newfile5_rel = "./newfile5";
char *path_newfile6 = "/tmp/fstrace-test-dir/newfile6";
char *path_newfile7_rel = "./newfile7";
char *path_newlink0 = "/tmp/fstrace-test-dir/newlink0";
char *path_newlink1_rel = "./newlink1";
char *path_newlink2_rel = "./newlink2";
char *path_newlink3_rel = "./newlink3";
char *path_newlink4 = "/tmp/fstrace-test-dir/newlink4";
char *path_newlink5_rel = "./newlink5";
char *path_newlink5 = "/tmp/fstrace-test-dir/newlink5";
char *path_newlink6_rel = "./newlink6";
char *tempdir = "/tmp/fstrace-test-dir";
char *path_newdir0 = "/tmp/fstrace-test-dir/newdir0";
char *path_newdir1_trailing_slash_rel = "./newdir1/";
char *path_newdir2_rel = "./newdir2";
char *path_newdir3 = "/tmp/fstrace-test-dir/newdir3";
char *path_newdir4_trailing_slash_rel = "./newdir4/";
char *path_newdir5_rel = "./newdir5";
char *path_newdir6 = "/tmp/fstrace-test-dir/newdir6";
char *path_newdir7_trailing_slash_rel = "./newdir7/";
char *path_newdir8_rel = "./newdir8";
char *path_usr_bin = "/usr/bin";

void setup()
{

  int num_test_files = 15;
  if (access(tempdir, F_OK) != -1)
  {
    printf("Removing existing tempdir\n");
    char command[100];
    sprintf(command, "rm -rf %s", tempdir);
    system(command);
  }
  syscall(__NR_mkdir, tempdir, 0777);

  for (int i = 0; i < num_test_files; i++)
  {
    char dir[sizeof(tempdir) + 30];
    char file[sizeof(tempdir) + 30];
    char fileLink[sizeof(tempdir) + 30];
    char dirLink[sizeof(tempdir) + 30];
    snprintf(dirLink, sizeof(dirLink), "%s/dir%d.link", tempdir, i);
    sprintf(dir, "%s/dir%d", tempdir, i);
    sprintf(fileLink, "%s/file%d.link", tempdir, i);
    sprintf(file, "%s/file%d", tempdir, i);
    syscall(__NR_mkdir, dir, 0777);
    syscall(__NR_open, file, O_CREAT | O_RDWR, 0777);
    syscall(__NR_symlink, file, fileLink);
    syscall(__NR_symlink, dir, dirLink);
  }
}

std::string filter_output(std::string output)
{
  std::istringstream iss(output);
  std::string line;
  std::string trimmed_output;
  while (std::getline(iss, line))
  {
    // ignore coverage file
    if (line.find("approval-tests.dir/tests/approval-tests/approval-tests.cc.gcda") == std::string::npos)
    {
      trimmed_output += line + "\n";
    }
  }
  return trimmed_output;
}

void testfn_creat()
{
  syscall(__NR_chdir, tempdir);
  int tempfd;
  tempfd = syscall(__NR_creat, path_newfile0, 0666 /* rw-rw-rw- */);
  syscall(__NR_close, tempfd);
  tempfd = syscall(__NR_creat, path_newfile1_rel, 0666 /* rw-rw-rw- */);
  syscall(__NR_close, tempfd);

  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Creat)
{
  setup();
  std::string output = trace_testfn(testfn_creat);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "WF /tmp/fstrace-test-dir/newfile0\n"
               "WF /tmp/fstrace-test-dir/newfile1\n"

  );
}

void testfn_open()
{
  syscall(__NR_chdir, tempdir);
  int tempfd;
  tempfd = syscall(__NR_open, path_newfile2, O_CREAT, 0666);
  syscall(__NR_close, tempfd);
  tempfd = syscall(__NR_open, path_newfile3_rel, O_CREAT, 0666);
  syscall(__NR_close, tempfd);
  tempfd = syscall(__NR_open, path_file0, O_RDONLY);
  syscall(__NR_close, tempfd);
  tempfd = syscall(__NR_open, path_file2_rel_irregular, O_RDONLY);
  syscall(__NR_close, tempfd);
  tempfd = syscall(__NR_open, path_file1, O_RDWR);
  syscall(__NR_close, tempfd);

  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Open)
{
  setup();
  std::string output = trace_testfn(testfn_open);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "WF /tmp/fstrace-test-dir/newfile2\n"
               "WF /tmp/fstrace-test-dir/newfile3\n"
               "RF /tmp/fstrace-test-dir/file0\n"
               "RF /tmp/fstrace-test-dir/file2\n"
               "WF /tmp/fstrace-test-dir/file1\n"

  );
}

void testfn_openat2()
{
  syscall(__NR_chdir, tempdir);
  struct open_how how = {};
  memset(&how, 0, sizeof(how));

  how.flags = O_RDONLY | O_DIRECTORY;
  int dirfd = syscall(__NR_openat2, AT_FDCWD, tempdir, &how, sizeof(how));
  int tempfd;

  how.flags = O_RDONLY;
  tempfd = syscall(__NR_openat2, dirfd, path_file0, &how, sizeof(how));
  syscall(__NR_close, tempfd);
  how.flags = O_RDWR;
  tempfd = syscall(__NR_openat2, dirfd, path_file0, &how, sizeof(how));
  syscall(__NR_close, tempfd);
  how.flags = O_WRONLY;
  tempfd = syscall(__NR_openat2, dirfd, path_doesnotexist, &how, sizeof(how));
  how.flags = O_RDONLY;
  tempfd = syscall(__NR_openat2, AT_FDCWD, path_doesnotexist_rel, &how, sizeof(how));
  how.flags = O_RDWR;
  tempfd = syscall(__NR_openat2, AT_FDCWD, path_doesnotexist_rel, &how, sizeof(how));
  how.flags = O_RDONLY;
  tempfd = syscall(__NR_openat2, AT_FDCWD, path_dir0_trailing_slash_rel, &how, sizeof(how));
  syscall(__NR_close, tempfd);
  how.flags = O_RDWR;
  tempfd = syscall(__NR_openat2, AT_FDCWD, path_dir0_trailing_slash_rel, &how, sizeof(how));
  syscall(__NR_close, tempfd);
  how.flags = O_RDONLY | O_DIRECTORY;
  tempfd = syscall(__NR_openat2, AT_FDCWD, path_dir0_trailing_slash_rel, &how, sizeof(how));
  syscall(__NR_close, tempfd);
  how.flags = O_RDWR | O_DIRECTORY;
  tempfd = syscall(__NR_openat2, dirfd, path_dir0_rel, &how, sizeof(how));
  syscall(__NR_close, tempfd);
  how.flags = O_RDONLY | O_DIRECTORY;
  tempfd = syscall(__NR_openat2, AT_FDCWD, path_dir0_rel, &how, sizeof(how));
  syscall(__NR_close, tempfd);

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Openat2)
{
  setup();
  std::string output = trace_testfn(testfn_openat2);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RD /tmp/fstrace-test-dir\n"
               "RF /tmp/fstrace-test-dir/file0\n"
               "WF /tmp/fstrace-test-dir/file0\n"
               "WX /tmp/fstrace-test-dir/does-not-exist\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "WX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "WD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "WD /tmp/fstrace-test-dir/dir0\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

  );
}

void testfn_openat()
{
  syscall(__NR_chdir, tempdir);
  int dirfd = syscall(__NR_open, tempdir, O_RDONLY | O_DIRECTORY);
  int tempfd;

  tempfd = syscall(__NR_openat, dirfd, path_file0, O_RDONLY);
  syscall(__NR_close, tempfd);
  tempfd = syscall(__NR_openat, dirfd, path_file0, O_RDWR);
  syscall(__NR_close, tempfd);
  tempfd = syscall(__NR_openat, dirfd, path_doesnotexist, O_WRONLY);
  tempfd = syscall(__NR_openat, dirfd, path_doesnotexist, O_RDWR);
  syscall(__NR_openat, AT_FDCWD, path_doesnotexist_rel, O_RDONLY);
  syscall(__NR_openat, AT_FDCWD, path_doesnotexist_rel, O_RDWR);
  tempfd = syscall(__NR_openat, AT_FDCWD, path_dir0_trailing_slash_rel, O_RDONLY);
  syscall(__NR_close, tempfd);
  tempfd = syscall(__NR_openat, AT_FDCWD, path_dir0_trailing_slash_rel, O_RDWR);
  syscall(__NR_close, tempfd);
  tempfd = syscall(__NR_openat, AT_FDCWD, path_dir0_trailing_slash_rel, O_RDONLY | O_DIRECTORY);
  syscall(__NR_close, tempfd);
  tempfd = syscall(__NR_openat, dirfd, path_dir0_rel, O_RDWR | O_DIRECTORY);
  syscall(__NR_close, tempfd);
  tempfd = syscall(__NR_openat, AT_FDCWD, path_dir0_rel, O_RDWR | O_DIRECTORY);
  syscall(__NR_close, tempfd);

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Openat)
{
  setup();
  std::string output = trace_testfn(testfn_openat);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RD /tmp/fstrace-test-dir\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "WF /tmp/fstrace-test-dir/file0\n"
               "WX /tmp/fstrace-test-dir/does-not-exist\n"
               "WX /tmp/fstrace-test-dir/does-not-exist\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "WX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "WD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "WD /tmp/fstrace-test-dir/dir0\n"
               "WD /tmp/fstrace-test-dir/dir0\n"

  );
}
void testfn_stat()
{
  struct stat statbuf;
  syscall(__NR_chdir, tempdir);

  // __NR_stat
  syscall(__NR_stat, path_file0, &statbuf);
  syscall(__NR_stat, path_doesnotexist, &statbuf);
  syscall(__NR_stat, path_dir0_trailing_slash, &statbuf);
  syscall(__NR_stat, path_dir0, &statbuf);

  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Stat)
{
  setup();
  std::string output = trace_testfn(testfn_stat);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

  );
}

void testfn_newfstatat()
{
  struct stat statbuf;
  syscall(__NR_chdir, tempdir);
  int dirfd = syscall(__NR_open, tempdir, O_RDONLY | O_DIRECTORY);

  // __NR_newfstatat AT_FDCWD relative path
  syscall(__NR_newfstatat, AT_FDCWD, path_file0_rel, &statbuf, 0);
  syscall(__NR_newfstatat, AT_FDCWD, path_doesnotexist_rel, &statbuf, 0);
  syscall(__NR_newfstatat, AT_FDCWD, path_dir0_trailing_slash_rel, &statbuf, 0);
  syscall(__NR_newfstatat, AT_FDCWD, path_dir0_rel, &statbuf, 0);

  // __NR_newfstatat AT_FDCWD absolute path
  syscall(__NR_newfstatat, AT_FDCWD, path_file0, &statbuf, 0);
  syscall(__NR_newfstatat, AT_FDCWD, path_doesnotexist, &statbuf, 0);
  syscall(__NR_newfstatat, AT_FDCWD, path_dir0_trailing_slash, &statbuf, 0);
  syscall(__NR_newfstatat, AT_FDCWD, path_dir0, &statbuf, 0);

  // __NR_newfstatat dirfd relative path
  syscall(__NR_newfstatat, dirfd, path_file0_rel, &statbuf, 0);
  syscall(__NR_newfstatat, dirfd, path_doesnotexist_rel, &statbuf, 0);
  syscall(__NR_newfstatat, dirfd, path_dir0_trailing_slash_rel, &statbuf, 0);
  syscall(__NR_newfstatat, dirfd, path_dir0_rel, &statbuf, 0);

  // __NR_newfstatat dirfd absolute path
  syscall(__NR_newfstatat, dirfd, path_file0, &statbuf, 0);
  syscall(__NR_newfstatat, dirfd, path_doesnotexist, &statbuf, 0);
  syscall(__NR_newfstatat, dirfd, path_dir0_trailing_slash, &statbuf, 0);
  syscall(__NR_newfstatat, dirfd, path_dir0, &statbuf, 0);

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Newfstatat)
{
  setup();
  std::string output = trace_testfn(testfn_newfstatat);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RD /tmp/fstrace-test-dir\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

  );
}

void testfn_lstat()
{
  struct stat statbuf;
  syscall(__NR_chdir, tempdir);

  // __NR_lstat relative path
  syscall(__NR_lstat, path_file0_rel, &statbuf);
  syscall(__NR_lstat, path_doesnotexist_rel, &statbuf);
  syscall(__NR_lstat, path_dir0_trailing_slash_rel, &statbuf);
  syscall(__NR_lstat, path_dir0_rel, &statbuf);

  // __NR_lstat absolute path
  syscall(__NR_lstat, path_file0, &statbuf);
  syscall(__NR_lstat, path_doesnotexist, &statbuf);
  syscall(__NR_lstat, path_dir0_trailing_slash, &statbuf);
  syscall(__NR_lstat, path_dir0, &statbuf);

  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Lstat)
{
  setup();
  std::string output = trace_testfn(testfn_lstat);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

  );
}

void testfn_statx()
{
  // int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf);
  struct statx statxbuf;
  syscall(__NR_chdir, tempdir);
  int flags = AT_STATX_SYNC_AS_STAT;
  int mask = STATX_BASIC_STATS;
  int dirfd = syscall(__NR_open, tempdir, O_RDONLY | O_DIRECTORY);

  // __NR_statx dirfd relative path
  syscall(__NR_statx, dirfd, path_file0_rel, flags, mask, &statxbuf);
  syscall(__NR_statx, dirfd, path_doesnotexist_rel, flags, mask, &statxbuf);
  syscall(__NR_statx, dirfd, path_dir0_trailing_slash_rel, flags, mask, &statxbuf);
  syscall(__NR_statx, dirfd, path_dir0_rel, flags, mask, &statxbuf);

  // __NR_statx dirfd absolute path
  syscall(__NR_statx, dirfd, path_file0, flags, mask, &statxbuf);
  syscall(__NR_statx, dirfd, path_doesnotexist, flags, mask, &statxbuf);
  syscall(__NR_statx, dirfd, path_dir0_trailing_slash, flags, mask, &statxbuf);
  syscall(__NR_statx, dirfd, path_dir0, flags, mask, &statxbuf);

  // __NR_statx AT_FDCWD relative path
  syscall(__NR_statx, AT_FDCWD, path_file0_rel, flags, mask, &statxbuf);
  syscall(__NR_statx, AT_FDCWD, path_doesnotexist_rel, flags, mask, &statxbuf);
  syscall(__NR_statx, AT_FDCWD, path_dir0_trailing_slash_rel, flags, mask, &statxbuf);
  syscall(__NR_statx, AT_FDCWD, path_dir0_rel, flags, mask, &statxbuf);

  // // __NR_statx AT_FDCWD absolute path
  syscall(__NR_statx, AT_FDCWD, path_file0, flags, mask, &statxbuf);
  syscall(__NR_statx, AT_FDCWD, path_doesnotexist, flags, mask, &statxbuf);
  syscall(__NR_statx, AT_FDCWD, path_dir0_trailing_slash, flags, mask, &statxbuf);
  syscall(__NR_statx, AT_FDCWD, path_dir0, flags, mask, &statxbuf);

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Statx)
{
  setup();
  std::string output = trace_testfn(testfn_statx);
  std::string trimmed_output = filter_output(output);

  printf("trimmed_output: %s\n", trimmed_output.c_str());

  EXPECT_STREQ(trimmed_output.c_str(),

               "RD /tmp/fstrace-test-dir\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

  );
}

void testfn_exec1()
{
  char *argv[] = {"cat", path_file0, NULL};
  char *envp[] = {NULL};
  syscall(__NR_execve, "/usr/bin/cat", argv, envp);

  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Exec1)
{
  setup();
  std::string output = trace_testfn(testfn_exec1);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RF /usr/bin/cat\n"
               "RX /etc/ld.so.preload\n"
               "RF /etc/ld.so.cache\n"
               "RF /etc/ld.so.cache\n"
               "RF /lib/x86_64-linux-gnu/libc.so.6\n"
               "RF /lib/x86_64-linux-gnu/libc.so.6\n"
               "RF /tmp/fstrace-test-dir/file0\n"
               "RF /tmp/fstrace-test-dir/file0\n"

  );
}
void testfn_exec2()
{
  syscall(__NR_chdir, path_usr_bin);

  char *argv[] = {"cat", path_file0, NULL};
  char *envp[] = {NULL};
  syscall(__NR_execve, "./cat", argv, envp);

  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Exec2)
{
  setup();
  std::string output = trace_testfn(testfn_exec2);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RF /usr/bin/cat\n"
               "RX /etc/ld.so.preload\n"
               "RF /etc/ld.so.cache\n"
               "RF /etc/ld.so.cache\n"
               "RF /lib/x86_64-linux-gnu/libc.so.6\n"
               "RF /lib/x86_64-linux-gnu/libc.so.6\n"
               "RF /tmp/fstrace-test-dir/file0\n"
               "RF /tmp/fstrace-test-dir/file0\n"

  );
}
void testfn_exec3()
{
  int dirfd = syscall(__NR_open, path_usr_bin, O_RDONLY | O_DIRECTORY);

  char *argv[] = {"cat", path_file0, NULL};
  char *envp[] = {NULL};
  syscall(__NR_execveat, AT_FDCWD, "/usr/bin/cat", argv, envp, 0);

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Exec3)
{
  setup();
  std::string output = trace_testfn(testfn_exec3);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RD /usr/bin\n"
               "RF /usr/bin/cat\n"
               "RX /etc/ld.so.preload\n"
               "RF /etc/ld.so.cache\n"
               "RF /etc/ld.so.cache\n"
               "RF /lib/x86_64-linux-gnu/libc.so.6\n"
               "RF /lib/x86_64-linux-gnu/libc.so.6\n"
               "RF /tmp/fstrace-test-dir/file0\n"
               "RF /tmp/fstrace-test-dir/file0\n"

  );
}
void testfn_exec4()
{
  syscall(__NR_chdir, path_usr_bin);
  int dirfd = syscall(__NR_open, path_usr_bin, O_RDONLY | O_DIRECTORY);

  char *argv[] = {"cat", path_file0, NULL};
  char *envp[] = {NULL};
  syscall(__NR_execveat, AT_FDCWD, "./cat", argv, envp, 0);

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Exec4)
{
  setup();
  std::string output = trace_testfn(testfn_exec4);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RD /usr/bin\n"
               "RF /usr/bin/cat\n"
               "RX /etc/ld.so.preload\n"
               "RF /etc/ld.so.cache\n"
               "RF /etc/ld.so.cache\n"
               "RF /lib/x86_64-linux-gnu/libc.so.6\n"
               "RF /lib/x86_64-linux-gnu/libc.so.6\n"
               "RF /tmp/fstrace-test-dir/file0\n"
               "RF /tmp/fstrace-test-dir/file0\n"

  );
}
void testfn_exec5()
{
  int dirfd = syscall(__NR_open, path_usr_bin, O_RDONLY | O_DIRECTORY);

  char *argv[] = {"cat", path_file0, NULL};
  char *envp[] = {NULL};
  syscall(__NR_execveat, dirfd, "/usr/bin/cat", argv, envp, 0);

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Exec5)
{
  setup();
  std::string output = trace_testfn(testfn_exec5);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RD /usr/bin\n"
               "RF /usr/bin/cat\n"
               "RX /etc/ld.so.preload\n"
               "RF /etc/ld.so.cache\n"
               "RF /etc/ld.so.cache\n"
               "RF /lib/x86_64-linux-gnu/libc.so.6\n"
               "RF /lib/x86_64-linux-gnu/libc.so.6\n"
               "RF /tmp/fstrace-test-dir/file0\n"
               "RF /tmp/fstrace-test-dir/file0\n"

  );
}
void testfn_exec6()
{
  syscall(__NR_chdir, path_usr_bin);
  int dirfd = syscall(__NR_open, path_usr_bin, O_RDONLY | O_DIRECTORY);

  char *argv[] = {"cat", path_file0, NULL};
  char *envp[] = {NULL};
  syscall(__NR_execveat, dirfd, "./cat", argv, envp, 0);

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Exec6)
{
  setup();
  std::string output = trace_testfn(testfn_exec6);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RD /usr/bin\n"
               "RF /usr/bin/cat\n"
               "RX /etc/ld.so.preload\n"
               "RF /etc/ld.so.cache\n"
               "RF /etc/ld.so.cache\n"
               "RF /lib/x86_64-linux-gnu/libc.so.6\n"
               "RF /lib/x86_64-linux-gnu/libc.so.6\n"
               "RF /tmp/fstrace-test-dir/file0\n"
               "RF /tmp/fstrace-test-dir/file0\n"

  );
}

void testfn_readlink()
{
  syscall(__NR_chdir, tempdir);
  int dirfd = syscall(__NR_open, tempdir, O_RDONLY | O_DIRECTORY);
  char buf[PATH_MAX];

  // __NR_readlink absolute path
  syscall(__NR_readlink, path_file0_link, buf, sizeof(buf));
  syscall(__NR_readlink, path_doesnotexist_link, buf, sizeof(buf));
  syscall(__NR_readlink, path_dir0_link, buf, sizeof(buf));

  // __NR_readlink relative path
  syscall(__NR_readlink, path_file0_link_rel, buf, sizeof(buf));
  syscall(__NR_readlink, path_doesnotexist_link_rel, buf, sizeof(buf));
  syscall(__NR_readlink, path_dir0_link_rel, buf, sizeof(buf));

  // __NR_readlinkat AT_FDCWD relative path
  syscall(__NR_readlinkat, AT_FDCWD, path_file0_link_rel, buf, sizeof(buf));
  syscall(__NR_readlinkat, AT_FDCWD, path_doesnotexist_link_rel, buf, sizeof(buf));
  syscall(__NR_readlinkat, AT_FDCWD, path_dir0_link_rel, buf, sizeof(buf));

  // __NR_readlinkat AT_FDCWD absolute path
  syscall(__NR_readlinkat, AT_FDCWD, path_file0_link, buf, sizeof(buf));
  syscall(__NR_readlinkat, AT_FDCWD, path_doesnotexist_link, buf, sizeof(buf));
  syscall(__NR_readlinkat, AT_FDCWD, path_dir0_link, buf, sizeof(buf));

  // __NR_readlinkat dirfd relative path
  syscall(__NR_readlinkat, dirfd, path_file0_link_rel, buf, sizeof(buf));
  syscall(__NR_readlinkat, dirfd, path_doesnotexist_link_rel, buf, sizeof(buf));
  syscall(__NR_readlinkat, dirfd, path_dir0_link_rel, buf, sizeof(buf));

  // __NR_readlinkat dirfd absolute path
  syscall(__NR_readlinkat, dirfd, path_file0_link, buf, sizeof(buf));
  syscall(__NR_readlinkat, dirfd, path_doesnotexist_link, buf, sizeof(buf));
  syscall(__NR_readlinkat, dirfd, path_dir0_link, buf, sizeof(buf));

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Readlink)
{
  setup();
  std::string output = trace_testfn(testfn_readlink);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RD /tmp/fstrace-test-dir\n"

               "RL /tmp/fstrace-test-dir/file0.link\n"
               "RX /tmp/fstrace-test-dir/does-not-exist.link\n"
               "RL /tmp/fstrace-test-dir/dir0.link\n"

               "RL /tmp/fstrace-test-dir/file0.link\n"
               "RX /tmp/fstrace-test-dir/does-not-exist.link\n"
               "RL /tmp/fstrace-test-dir/dir0.link\n"

               "RL /tmp/fstrace-test-dir/file0.link\n"
               "RX /tmp/fstrace-test-dir/does-not-exist.link\n"
               "RL /tmp/fstrace-test-dir/dir0.link\n"

               "RL /tmp/fstrace-test-dir/file0.link\n"
               "RX /tmp/fstrace-test-dir/does-not-exist.link\n"
               "RL /tmp/fstrace-test-dir/dir0.link\n"

               "RL /tmp/fstrace-test-dir/file0.link\n"
               "RX /tmp/fstrace-test-dir/does-not-exist.link\n"
               "RL /tmp/fstrace-test-dir/dir0.link\n"

               "RL /tmp/fstrace-test-dir/file0.link\n"
               "RX /tmp/fstrace-test-dir/does-not-exist.link\n"
               "RL /tmp/fstrace-test-dir/dir0.link\n"

  );
}

void testfn_access()
{
  syscall(__NR_chdir, tempdir);
  int dirfd = open(tempdir, O_DIRECTORY, 0);

  // __NR_access relative path
  syscall(__NR_access, path_file0_rel, R_OK);
  syscall(__NR_access, path_doesnotexist_rel, R_OK);
  syscall(__NR_access, path_dir0_trailing_slash_rel, R_OK);
  syscall(__NR_access, path_dir0_rel, R_OK);

  // __NR_access absolute path
  syscall(__NR_access, path_file0, R_OK);
  syscall(__NR_access, path_doesnotexist, R_OK);
  syscall(__NR_access, path_dir0_trailing_slash, R_OK);
  syscall(__NR_access, path_dir0, R_OK);

  // __NR_faccessat2 AT_FDCWD relative path
  syscall(__NR_faccessat2, AT_FDCWD, path_file0_rel, R_OK, 0);
  syscall(__NR_faccessat2, AT_FDCWD, path_doesnotexist_rel, R_OK, 0);
  syscall(__NR_faccessat2, AT_FDCWD, path_dir0_trailing_slash_rel, R_OK, 0);
  syscall(__NR_faccessat2, AT_FDCWD, path_dir0_rel, R_OK, 0);

  // __NR_faccessat2 AT_FDCWD absolute path
  syscall(__NR_faccessat2, AT_FDCWD, path_file0, R_OK, 0);
  syscall(__NR_faccessat2, AT_FDCWD, path_doesnotexist, R_OK, 0);
  syscall(__NR_faccessat2, AT_FDCWD, path_dir0_trailing_slash, R_OK, 0);
  syscall(__NR_faccessat2, AT_FDCWD, path_dir0, R_OK, 0);

  // __NR_faccessat2 dirfd relative path
  syscall(__NR_faccessat2, dirfd, path_file0_rel, R_OK, 0);
  syscall(__NR_faccessat2, dirfd, path_doesnotexist_rel, R_OK, 0);
  syscall(__NR_faccessat2, dirfd, path_dir0_trailing_slash_rel, R_OK, 0);
  syscall(__NR_faccessat2, dirfd, path_dir0_rel, R_OK, 0);

  // __NR_faccessat2 dirfd absolute path
  syscall(__NR_faccessat2, dirfd, path_file0, R_OK, 0);
  syscall(__NR_faccessat2, dirfd, path_doesnotexist, R_OK, 0);
  syscall(__NR_faccessat2, dirfd, path_dir0_trailing_slash, R_OK, 0);
  syscall(__NR_faccessat2, dirfd, path_dir0, R_OK, 0);

  // __NR_faccessat AT_FDCWD relative path
  syscall(__NR_faccessat, AT_FDCWD, path_file0_rel, R_OK, 0);
  syscall(__NR_faccessat, AT_FDCWD, path_doesnotexist_rel, R_OK, 0);
  syscall(__NR_faccessat, AT_FDCWD, path_dir0_trailing_slash_rel, R_OK, 0);
  syscall(__NR_faccessat, AT_FDCWD, path_dir0_rel, R_OK, 0);

  // __NR_faccessat AT_FDCWD absolute path
  syscall(__NR_faccessat, AT_FDCWD, path_file0, R_OK, 0);
  syscall(__NR_faccessat, AT_FDCWD, path_doesnotexist, R_OK, 0);
  syscall(__NR_faccessat, AT_FDCWD, path_dir0_trailing_slash, R_OK, 0);
  syscall(__NR_faccessat, AT_FDCWD, path_dir0, R_OK, 0);

  // __NR_faccessat dirfd relative path
  syscall(__NR_faccessat, dirfd, path_file0_rel, R_OK, 0);
  syscall(__NR_faccessat, dirfd, path_doesnotexist_rel, R_OK, 0);
  syscall(__NR_faccessat, dirfd, path_dir0_trailing_slash_rel, R_OK, 0);
  syscall(__NR_faccessat, dirfd, path_dir0_rel, R_OK, 0);

  // __NR_faccessat dirfd absolute path
  syscall(__NR_faccessat, dirfd, path_file0, R_OK, 0);
  syscall(__NR_faccessat, dirfd, path_doesnotexist, R_OK, 0);
  syscall(__NR_faccessat, dirfd, path_dir0_trailing_slash, R_OK, 0);
  syscall(__NR_faccessat, dirfd, path_dir0, R_OK, 0);

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Access)
{
  setup();
  std::string output = trace_testfn(testfn_access);
  std::string trimmed_output = filter_output(output);

  EXPECT_STREQ(trimmed_output.c_str(),

               "RD /tmp/fstrace-test-dir\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

               "RF /tmp/fstrace-test-dir/file0\n"
               "RX /tmp/fstrace-test-dir/does-not-exist\n"
               "RD /tmp/fstrace-test-dir/dir0/\n"
               "RD /tmp/fstrace-test-dir/dir0\n"

  );
}

void testfn_unlink()
{
  syscall(__NR_chdir, tempdir);
  int dirfd = syscall(__NR_open, tempdir, O_RDONLY | O_DIRECTORY);

  syscall(__NR_unlink, path_file0_rel);
  syscall(__NR_unlink, path_file1);
  syscall(__NR_unlinkat, AT_FDCWD, path_file2_rel_irregular, 0);
  syscall(__NR_unlinkat, AT_FDCWD, path_file3, 0);
  syscall(__NR_unlinkat, dirfd, path_file4_rel, 0);
  syscall(__NR_unlinkat, dirfd, path_file_5, 0);

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Unlink)
{
  setup();
  std::string output = trace_testfn(testfn_unlink);
  std::string trimmed_output = filter_output(output);

  EXPECT_STRCASEEQ(trimmed_output.c_str(),

                   "RD /tmp/fstrace-test-dir\n"

                   "DX /tmp/fstrace-test-dir/file0\n"
                   "DX /tmp/fstrace-test-dir/file1\n"
                   "DX /tmp/fstrace-test-dir/file2\n"
                   "DX /tmp/fstrace-test-dir/file3\n"
                   "DX /tmp/fstrace-test-dir/file4\n"
                   "DX /tmp/fstrace-test-dir/file5\n"

  );
}

void testfn_getdents()
{
  int dirfd = syscall(__NR_open, tempdir, O_RDONLY | O_DIRECTORY);
  struct dirent dirent;

  syscall(__NR_getdents, dirfd, &dirent, sizeof(dirent));
  syscall(__NR_getdents64, dirfd, &dirent, sizeof(dirent));

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Getdents)
{
  setup();
  std::string output = trace_testfn(testfn_getdents);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RD /tmp/fstrace-test-dir\n"

               "ED /tmp/fstrace-test-dir\n"
               "ED /tmp/fstrace-test-dir\n"

  );
}

void testfn_rmdir()
{
  syscall(__NR_chdir, tempdir);

  syscall(__NR_rmdir, path_dir0_trailing_slash_rel);
  syscall(__NR_rmdir, path_dir1_rel);

  syscall(__NR_rmdir, path_dir2_trailing_slash);
  syscall(__NR_rmdir, path_dir3);

  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Rmdir)
{
  setup();
  std::string output = trace_testfn(testfn_rmdir);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "DX /tmp/fstrace-test-dir/dir0/\n"
               "DX /tmp/fstrace-test-dir/dir1\n"

               "DX /tmp/fstrace-test-dir/dir2/\n"
               "DX /tmp/fstrace-test-dir/dir3\n"

  );
}

void testfn_rename()
{
  syscall(__NR_chdir, tempdir);
  int dirfd = open(tempdir, O_DIRECTORY, 0);

  syscall(__NR_rename, path_file0_rel, path_newfile0_rel);
  syscall(__NR_rename, path_file1, path_newfile1);

  syscall(__NR_renameat, AT_FDCWD, path_file2, dirfd, path_newfile2);
  syscall(__NR_renameat, AT_FDCWD, path_file3_rel, dirfd, path_newfile3_rel);

  syscall(__NR_renameat2, AT_FDCWD, path_file4, dirfd, path_newfile4, 0);
  syscall(__NR_renameat2, AT_FDCWD, path_file5_rel, dirfd, path_newfile5_rel, 0);

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Rename)
{
  setup();
  std::string output = trace_testfn(testfn_rename);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RD /tmp/fstrace-test-dir\n"

               "DX /tmp/fstrace-test-dir/file0\n"
               "WF /tmp/fstrace-test-dir/newfile0\n"
               "DX /tmp/fstrace-test-dir/file1\n"
               "WF /tmp/fstrace-test-dir/newfile1\n"

               "DX /tmp/fstrace-test-dir/file2\n"
               "WF /tmp/fstrace-test-dir/newfile2\n"
               "DX /tmp/fstrace-test-dir/file3\n"
               "WF /tmp/fstrace-test-dir/newfile3\n"

               "DX /tmp/fstrace-test-dir/file4\n"
               "WF /tmp/fstrace-test-dir/newfile4\n"
               "DX /tmp/fstrace-test-dir/file5\n"
               "WF /tmp/fstrace-test-dir/newfile5\n"

  );
}

void testfn_mkdir()
{
  syscall(__NR_chdir, tempdir);
  int dirfd = open(tempdir, O_DIRECTORY, 0);

  syscall(__NR_mkdir, path_newdir0, 0777);
  syscall(__NR_mkdir, path_newdir1_trailing_slash_rel, 0777);
  syscall(__NR_mkdir, path_newdir2_rel, 0777);

  syscall(__NR_mkdirat, AT_FDCWD, path_newdir3, 0777);
  syscall(__NR_mkdirat, AT_FDCWD, path_newdir4_trailing_slash_rel, 0777);
  syscall(__NR_mkdirat, AT_FDCWD, path_newdir5_rel, 0777);

  syscall(__NR_mkdirat, dirfd, path_newdir6, 0777);
  syscall(__NR_mkdirat, dirfd, path_newdir7_trailing_slash_rel, 0777);
  syscall(__NR_mkdirat, dirfd, path_newdir8_rel, 0777);

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Mkdir)
{
  setup();
  std::string output = trace_testfn(testfn_mkdir);
  std::string trimmed_output = filter_output(output);

  EXPECT_STREQ(trimmed_output.c_str(),

               "RD /tmp/fstrace-test-dir\n"

               "WD /tmp/fstrace-test-dir/newdir0\n"
               "WD /tmp/fstrace-test-dir/newdir1/\n"
               "WD /tmp/fstrace-test-dir/newdir2\n"

               "WD /tmp/fstrace-test-dir/newdir3\n"
               "WD /tmp/fstrace-test-dir/newdir4/\n"
               "WD /tmp/fstrace-test-dir/newdir5\n"

               "WD /tmp/fstrace-test-dir/newdir6\n"
               "WD /tmp/fstrace-test-dir/newdir7/\n"
               "WD /tmp/fstrace-test-dir/newdir8\n"

  );
}

void testfn_chmod()
{
  syscall(__NR_chdir, tempdir);
  int dirfd = open(tempdir, O_DIRECTORY, 0);

  syscall(__NR_chmod, path_file0, 0777);
  syscall(__NR_chmod, path_file1_rel, 0777);

  syscall(__NR_fchmodat, AT_FDCWD, path_file2, 0777, 0);
  syscall(__NR_fchmodat, AT_FDCWD, path_file3_rel, 0777, 0);

  syscall(__NR_fchmodat, dirfd, path_file4, 0777, 0);
  syscall(__NR_fchmodat, dirfd, path_file5_rel, 0777, 0);

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Chmod)
{
  setup();
  std::string output = trace_testfn(testfn_chmod);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RD /tmp/fstrace-test-dir\n"

               "WF /tmp/fstrace-test-dir/file0\n"
               "WF /tmp/fstrace-test-dir/file1\n"

               "WF /tmp/fstrace-test-dir/file2\n"
               "WF /tmp/fstrace-test-dir/file3\n"

               "WF /tmp/fstrace-test-dir/file4\n"
               "WF /tmp/fstrace-test-dir/file5\n"

  );
}

void testfn_symlink()
{
  syscall(__NR_chdir, tempdir);
  int dirfd = open(tempdir, O_DIRECTORY, 0);

  syscall(__NR_symlink, path_file0, path_newlink0);
  syscall(__NR_symlink, path_file1_rel, path_newlink1_rel);
  syscall(__NR_symlink, path_file2, path_newlink2_rel);

  syscall(__NR_symlinkat, path_file3, AT_FDCWD, path_newlink3_rel);
  syscall(__NR_symlinkat, path_file3, AT_FDCWD, path_newlink4);
  syscall(__NR_symlinkat, path_file5, dirfd, path_newlink5);
  syscall(__NR_symlinkat, path_file6, dirfd, path_newlink6_rel);

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Symlink)
{
  setup();
  std::string output = trace_testfn(testfn_symlink);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RD /tmp/fstrace-test-dir\n"

               "WL /tmp/fstrace-test-dir/newlink0\n"
               "WL /tmp/fstrace-test-dir/newlink1\n"
               "WL /tmp/fstrace-test-dir/newlink2\n"

               "WL /tmp/fstrace-test-dir/newlink3\n"
               "WL /tmp/fstrace-test-dir/newlink4\n"
               "WL /tmp/fstrace-test-dir/newlink5\n"
               "WL /tmp/fstrace-test-dir/newlink6\n"

  );
}

void testfn_link()
{
  syscall(__NR_chdir, tempdir);
  int dirfd = open(tempdir, O_DIRECTORY, 0);

  syscall(__NR_link, path_file0, path_newfile0);
  syscall(__NR_link, path_file1_rel, path_newfile1_rel);

  syscall(__NR_linkat, AT_FDCWD, path_file2, AT_FDCWD, path_newfile2, 0);
  syscall(__NR_linkat, AT_FDCWD, path_file3_rel, AT_FDCWD, path_newfile3_rel, 0);

  syscall(__NR_linkat, dirfd, path_file4, AT_FDCWD, path_newfile4, 0);
  syscall(__NR_linkat, dirfd, path_file5_rel, AT_FDCWD, path_newfile5_rel, 0);

  syscall(__NR_linkat, AT_FDCWD, path_file6, dirfd, path_newfile6, 0);
  syscall(__NR_linkat, AT_FDCWD, path_file7_rel, dirfd, path_newfile7_rel, 0);

  syscall(__NR_close, dirfd);
  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Link)
{
  setup();
  std::string output = trace_testfn(testfn_link);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "RD /tmp/fstrace-test-dir\n"

               "WF /tmp/fstrace-test-dir/newfile0\n"
               "WF /tmp/fstrace-test-dir/newfile1\n"

               "WF /tmp/fstrace-test-dir/newfile2\n"
               "WF /tmp/fstrace-test-dir/newfile3\n"

               "WF /tmp/fstrace-test-dir/newfile4\n"
               "WF /tmp/fstrace-test-dir/newfile5\n"

               "WF /tmp/fstrace-test-dir/newfile6\n"
               "WF /tmp/fstrace-test-dir/newfile7\n"

  );
}

void testfn_utimes()
{
  syscall(__NR_chdir, tempdir);

  struct timeval new_times[2];
  gettimeofday(&new_times[0], NULL);
  gettimeofday(&new_times[1], NULL);

  syscall(__NR_utimes, path_file0, new_times);
  syscall(__NR_utimes, path_file1_rel, new_times);

  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Utimes)
{
  setup();
  std::string output = trace_testfn(testfn_utimes);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "WF /tmp/fstrace-test-dir/file0\n"
               "WF /tmp/fstrace-test-dir/file1\n"

  );
}

void testfn_truncate()
{
  syscall(__NR_chdir, tempdir);

  syscall(__NR_truncate, path_file0, 0);
  syscall(__NR_truncate, path_file1_rel, 0);

  syscall(__NR_exit, EXIT_SUCCESS);
}
TEST(SyscallTestSuite, Truncate)
{
  setup();
  std::string output = trace_testfn(testfn_truncate);
  std::string trimmed_output = filter_output(output);
  EXPECT_STREQ(trimmed_output.c_str(),

               "WF /tmp/fstrace-test-dir/file0\n"
               "WF /tmp/fstrace-test-dir/file1\n"

  );
}

void testfn_child_process_fork()
{
  pid_t pid1 = syscall(__NR_fork);
  if (pid1 == 0)
  {
    pid_t pid2 = syscall(__NR_fork);
    if (pid2 == 0)
    {
      pid_t pid3 = syscall(__NR_fork);
      if (pid3 == 0)
      {
        syscall(__NR_truncate, path_file0, 0);
        syscall(__NR_exit, EXIT_SUCCESS);
      }
      else
      {
        syscall(__NR_truncate, path_file1, 0);
        syscall(__NR_wait4, pid3, NULL, 0, NULL);
        syscall(__NR_exit, EXIT_SUCCESS);
      }
    }
    else
    {
      syscall(__NR_truncate, path_file2, 0);
      syscall(__NR_wait4, pid2, NULL, 0, NULL);
      syscall(__NR_exit, EXIT_SUCCESS);
    }
  }
  else
  {
    pid_t pid4 = syscall(__NR_fork);
    if (pid4 == 0)
    {
      pid_t pid5 = syscall(__NR_fork);
      if (pid5 == 0)
      {
        syscall(__NR_truncate, path_file3, 0);
        syscall(__NR_exit, EXIT_SUCCESS);
      }
      else
      {
        syscall(__NR_truncate, path_file4, 0);
        syscall(__NR_wait4, pid5, NULL, 0, NULL);
        syscall(__NR_exit, EXIT_SUCCESS);
      }
    }
    else
    {
      pid_t pid6 = syscall(__NR_fork);
      if (pid6 == 0)
      {
        syscall(__NR_truncate, path_file5, 0);
        syscall(__NR_exit, EXIT_SUCCESS);
      }
      else
      {
        pid_t pid7 = syscall(__NR_fork);
        if (pid7 == 0)
        {
          syscall(__NR_truncate, path_file6, 0);
          syscall(__NR_exit, EXIT_SUCCESS);
        }
        else
        {
          syscall(__NR_truncate, path_file7, 0);
          syscall(__NR_wait4, pid1, NULL, 0, NULL);
          syscall(__NR_wait4, pid4, NULL, 0, NULL);
          syscall(__NR_wait4, pid6, NULL, 0, NULL);
          syscall(__NR_wait4, pid7, NULL, 0, NULL);
          syscall(__NR_exit, EXIT_SUCCESS);
        }
      }
    }
  }
}
TEST(SyscallTestSuite, ChildProcessFork)
{
  setup();
  std::string output = trace_testfn(testfn_child_process_fork);
  std::string trimmed_output = filter_output(output);

  std::string file0_access = "WF /tmp/fstrace-test-dir/file0\n", file1_access = "WF /tmp/fstrace-test-dir/file1\n",
              file2_access = "WF /tmp/fstrace-test-dir/file2\n", file3_access = "WF /tmp/fstrace-test-dir/file3\n",
              file4_access = "WF /tmp/fstrace-test-dir/file4\n", file5_access = "WF /tmp/fstrace-test-dir/file5\n",
              file6_access = "WF /tmp/fstrace-test-dir/file6\n", file7_access = "WF /tmp/fstrace-test-dir/file7\n",
              newline = "\n";

  EXPECT_PRED3(SubstringCountPredicate, trimmed_output, file0_access, 1);
  EXPECT_PRED3(SubstringCountPredicate, trimmed_output, file1_access, 1);
  EXPECT_PRED3(SubstringCountPredicate, trimmed_output, file2_access, 1);
  EXPECT_PRED3(SubstringCountPredicate, trimmed_output, file3_access, 1);
  EXPECT_PRED3(SubstringCountPredicate, trimmed_output, file4_access, 1);
  EXPECT_PRED3(SubstringCountPredicate, trimmed_output, file5_access, 1);
  EXPECT_PRED3(SubstringCountPredicate, trimmed_output, file6_access, 1);
  EXPECT_PRED3(SubstringCountPredicate, trimmed_output, file7_access, 1);

  EXPECT_PRED3(SubstringCountPredicate, trimmed_output, newline, 8);
}
