#!/bin/python3
import asyncio
import os
import struct
import uuid
from datetime import datetime

HOST = "0.0.0.0"
PORT = 44445
LOG_FILE = "server.log"


class CommandRequest:
    def __init__(self, content: bytes, cmd_type: str, time_out: int):
        self.content = content
        self.cmd_type = cmd_type
        self.time_out = time_out  # seconds (u16 in protocol)

    @staticmethod
    async def from_stream(reader: asyncio.StreamReader) -> "CommandRequest":
        # 1 byte: cmd_type (0=cmd, 1=python)
        t_raw = await reader.readexactly(1)
        t = t_raw[0]
        if t == 0:
            cmd_type = "cmd"
        elif t == 1:
            cmd_type = "python"
        elif t == 2:
            cmd_type = "php"
        else:
            raise ValueError(f"Unknown command type: {t}")

        # 2 bytes: timeout (u16 BE)
        timeout_raw = await reader.readexactly(2)
        time_out = struct.unpack(">H", timeout_raw)[0]

        # 4 bytes: content length (u32 BE)
        length_raw = await reader.readexactly(4)
        length = struct.unpack(">I", length_raw)[0]

        # content bytes
        content = await reader.readexactly(length)

        return CommandRequest(content=content, cmd_type=cmd_type, time_out=time_out)


async def send(writer: asyncio.StreamWriter, content: bytes) -> None:
    writer.write(struct.pack(">I", len(content)))
    writer.write(content)
    await writer.drain()


async def run_python(code: bytes, timeout_secs: int) -> bytes:
    # 写入临时文件
    file_id = uuid.uuid4().hex
    filename = f"/tmp/python{file_id}.py"
    try:
        with open(filename, "wb") as f:
            f.write(code)
    except Exception:
        return b"run python code fail"

    try:
        proc = await asyncio.create_subprocess_exec(
            "python3", filename,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_secs)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return f"python run timeout after {timeout_secs} seconds".encode()

        if proc.returncode == 0:
            return stdout
        else:
            return stderr
    except Exception as e:
        return f"python execution error: {e}".encode()
    finally:
        try:
            os.remove(filename)
        except FileNotFoundError:
            pass


async def run_php(code: bytes, timeout_secs: int) -> bytes:
    file_id = uuid.uuid4().hex
    filename = f"/tmp/php{file_id}.php"
    try:
        with open(filename, "wb") as f:
            f.write(code)
    except Exception:
        return b"run php code fail"

    try:
        proc = await asyncio.create_subprocess_exec(
            "php", "-d",
            "phar.readonly=0",
            filename,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_secs)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return f"php run timeout after {timeout_secs} seconds".encode()

        if proc.returncode == 0:
            return stdout
        else:
            return stderr
    except Exception as e:
        return f"php execution error: {e}".encode()
    finally:
        try:
            os.remove(filename)
        except FileNotFoundError:
            pass



async def run_cmd(cmd: str, timeout_secs: int) -> bytes:
    try:
        proc = await asyncio.create_subprocess_exec(
            "bash", "-c", cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_secs)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return f"Command timeout after {timeout_secs} millis: {cmd}".encode()

        if proc.returncode == 0:
            return stdout
        else:
            return stderr
    except Exception as e:
        return f"Command execution error: {e}".encode()


async def write_log(text: str) -> None:
    # 简单的异步写：放到线程池避免阻塞事件循环
    def _append():
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(text)
            f.write("\n")
            f.flush()

    await asyncio.to_thread(_append)


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    try:
        while True:
            try:
                command = await CommandRequest.from_stream(reader)
            except asyncio.IncompleteReadError:
                break  # 客户端断开
            except Exception as e:
                # 无法解析本次请求，关闭连接
                await write_log(f"[{datetime.now()}] parse error from {peer}: {e}")
                break

            if command.cmd_type == "cmd":
                resp = await run_cmd(command.content.decode(errors="ignore"), int(command.time_out))
            elif command.cmd_type == "python":
                resp = await run_python(command.content, int(command.time_out))
            elif command.cmd_type == "php":
                resp = await run_php(command.content, int(command.time_out))
            else:
                break

            await send(writer, resp)

            # 记录日志
            content_preview = command.content.decode(errors="ignore")
            log = (
                "-------------------------[ time: {} ]-------------------------\n"
                "execute======>:\n{}\n"
                "[result]======>:\n{}\n\n"
            ).format(datetime.now(), content_preview, resp.decode(errors="ignore"))
            await write_log(log)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets or [])
    print(f"Serving on {addrs}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
