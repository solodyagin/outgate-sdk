"""Keep Go test output and publish bounded failure context as CI annotations."""
import collections
import json
import subprocess
import sys


def escaped(value):
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main():
    tail = collections.deque(maxlen=20)
    with subprocess.Popen(
        ["go", "test", "-json", *sys.argv[1:]], stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
    ) as process:
        for line in process.stdout:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(line, end="", flush=True)
                tail.append(line[-4096:])
                continue
            output = event.get("Output", "")
            if output:
                print(output, end="", flush=True)
                tail.append(output[-4096:])
            if event.get("Action") == "fail":
                name = event.get("Test", event.get("Package", "go test"))
                detail = (name + "\n" + "".join(tail))[-12000:]
                print("::error title=Go test failed::" + escaped(detail), flush=True)
        return process.wait()


if __name__ == "__main__":
    sys.exit(main())
