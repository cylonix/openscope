"""northwind-webapp — trivial sample script (synthetic, MIT)."""


def greet(name: str) -> str:
    return f"Hello, {name}!"


def fib(n: int) -> int:
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


if __name__ == "__main__":
    print(greet("world"))
    print([fib(i) for i in range(10)])
