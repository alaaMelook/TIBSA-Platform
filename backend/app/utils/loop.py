import sys
import asyncio

def run_in_proactor_loop(coro_func, *args, **kwargs):
    """
    Runs an asynchronous coroutine function in a new thread with a new ProactorEventLoop.
    This is required on Windows when running under Uvicorn, because Uvicorn uses
    SelectorEventLoop which does not support asyncio subprocesses (used by Playwright).
    """
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro_func(*args, **kwargs))
    finally:
        try:
            loop.close()
        except:
            pass
