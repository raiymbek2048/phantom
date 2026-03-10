"""
Tool Runner — safely executes external security tools as subprocesses.

All tool execution goes through this module for:
- Timeout enforcement
- Output capture
- Error handling
- Logging
"""
import asyncio
import shutil
import structlog

logger = structlog.get_logger()


async def run_command(
    cmd: list[str],
    timeout: int = 60,
    input_data: str | None = None,
) -> str:
    """Run an external command and return its stdout output.

    Args:
        cmd: Command and arguments as a list
        timeout: Maximum execution time in seconds
        input_data: Optional stdin data

    Returns:
        stdout output as string

    Raises:
        ToolError: If the tool is not found or execution fails
    """
    tool_name = cmd[0]

    # Check if tool exists
    if not shutil.which(tool_name):
        raise ToolNotFoundError(f"Tool not found: {tool_name}. Make sure it's installed.")

    logger.info("tool_run", tool=tool_name, args=cmd[1:])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_data else None,
        )

        stdin_bytes = input_data.encode() if input_data else None
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_bytes),
            timeout=timeout,
        )

        output = stdout.decode("utf-8", errors="replace")

        if proc.returncode != 0:
            stderr_text = stderr.decode("utf-8", errors="replace")
            logger.warning(
                "tool_nonzero_exit",
                tool=tool_name,
                returncode=proc.returncode,
                stderr=stderr_text[:500],
            )

        logger.info("tool_complete", tool=tool_name, output_length=len(output))
        return output

    except asyncio.TimeoutError:
        logger.error("tool_timeout", tool=tool_name, timeout=timeout)
        try:
            proc.kill()
        except Exception:
            pass
        raise ToolTimeoutError(f"Tool {tool_name} timed out after {timeout}s")

    except FileNotFoundError:
        raise ToolNotFoundError(f"Tool not found: {tool_name}")

    except Exception as e:
        logger.error("tool_error", tool=tool_name, error=str(e))
        raise ToolError(f"Tool {tool_name} failed: {str(e)}")


class ToolError(Exception):
    pass


class ToolNotFoundError(ToolError):
    pass


class ToolTimeoutError(ToolError):
    pass
