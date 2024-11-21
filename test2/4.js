const { writeFile } = require("fs/promises");

writeFile("/tmp/hello.txt", "Hello, world!\n");
