const [mode, ...args] = process.argv.slice(2);

switch (mode) {
  case "argv":
    process.stdout.write(JSON.stringify(args));
    break;
  case "unicode": {
    const bytes = Buffer.from('{"message":"路径🔒"}');
    // Deliberately split a UTF-8 code point across writes.
    process.stdout.write(bytes.subarray(0, 14));
    setTimeout(() => process.stdout.write(bytes.subarray(14)), 10);
    break;
  }
  case "invalid-utf8":
    process.stdout.write(Buffer.from([0x7b, 0xff, 0x7d]));
    break;
  case "exit":
    process.stdout.write('{"ok":false}');
    process.stderr.write("diagnostic");
    process.exitCode = Number(args[0]);
    break;
  case "overflow-stdout":
    process.stdout.write("x".repeat(32_768));
    setInterval(() => {}, 1000);
    break;
  case "overflow-combined":
    process.stdout.write("x".repeat(700));
    process.stderr.write("y".repeat(700));
    setInterval(() => {}, 1000);
    break;
  case "hang":
    setInterval(() => {}, 1000);
    break;
  case "signal":
    process.kill(process.pid, "SIGTERM");
    break;
  default:
    process.exitCode = 99;
}
