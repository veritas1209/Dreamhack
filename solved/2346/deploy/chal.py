import secrets

random = secrets.SystemRandom()

CURVE_CODE_SNIPPET = """
import secrets

random = secrets.SystemRandom()

p = 0x100000000000000000000000000000000000000000000000000000000000001E7

class MyField:
    def __init__(self, v):
        if isinstance(v, MyField):
            self.v = v.v
        elif isinstance(v, int):
            self.v = v % p
        else:
            raise ValueError

    @staticmethod
    def random_element():
        return MyField(random.randint(0, p - 1))

    @staticmethod
    def _get_value(other):
        if isinstance(other, MyField):
            return other.v
        elif isinstance(other, int):
            return other
        else:
            raise NotImplemented

    def __eq__(self, other):
        return self.v == self._get_value(other)

    def __add__(self, other):
        return MyField(self.v + self._get_value(other))

    __radd__ = __add__

    def __mul__(self, other):
        return MyField(self.v * self._get_value(other))

    __rmul__ = __mul__

    def __sub__(self, other):
        return MyField(self.v - self._get_value(other))

    def __truediv__(self, other):
        ov = self._get_value(other)
        if ov == 0:
            raise ValueError
        return MyField(self.v * pow(ov, -1, p))

    def __str__(self):
        return str(self.v)

    def is_square(self):
        return pow(self.v, (p - 1) // 2, p) == 1

    def sqrt(self):
        return MyField(pow(self.v, (p + 1) // 4, p))


class MyCurve:
    order = {order}

    def __init__(self, x, y) -> None:
        self.x = MyField(x)
        self.y = MyField(y)

        assert x * x * x * x + x * x * x + x * x + x + 1 == y * y

    @staticmethod
    def random_element():
        while True:
            x = MyField.random_element()
            y_square = x * x * x * x + x * x * x + x * x + x + 1
            if y_square.is_square():
                y = y_square.sqrt()
                return MyCurve(x, y)

    def __eq__(self, other):
        if not isinstance(other, MyCurve):
            raise NotImplemented

        return self.x == other.x and self.y == other.y

    def __add__(self, other):
        if other is None:
            return self

        x, y, u, v = self.x, self.y, other.x, other.y

        try:
            {code}

        except ValueError:
            return None

        return MyCurve(x, y)

    __radd__ = __add__

    def __mul__(self, other):
        if not isinstance(other, int):
            raise NotImplemented

        other = other % self.order
        result, double = None, self

        while other:
            if other & 1:
                if result is None:
                    result = double
                else:
                    result = result + double

            double = double + double
            other >>= 1

        return result

    __rmul__ = __mul__
"""

ALLOWED = set("+-*/= xyuv0123456789")


def setup():
    order = int(input("Order? > "))

    code = []
    print("Give me code!")
    while True:
        line = input().strip()
        if not line:
            break

        if not set(line).issubset(ALLOWED):
            print("illegal character")
            exit(0)

        code.append(line)

    code = "\n            ".join(code)

    curve_code = CURVE_CODE_SNIPPET.format(order=order, code=code)

    with open("curve.py", "w") as f:
        f.write(curve_code)


def test():
    try:
        MyCurve = __import__("curve").MyCurve
    except:
        print(":(")
        exit(1)

    for _ in range(10_000):
        P = MyCurve.random_element()
        Q = MyCurve.random_element()

        try:
            T1 = P + Q
            T2 = Q + P
        except:
            print(":(")
            exit(1)

        if T1 != T2:
            print(":(")
            exit(1)
    print("Passed step 1...")

    for _ in range(10_000):
        P = MyCurve.random_element()
        Q = MyCurve.random_element()
        R = MyCurve.random_element()

        try:
            T1 = (P + Q) + R
            T2 = P + (Q + R)
        except:
            print(":(")
            exit(1)

        if T1 != T2:
            print(":(")
            exit(1)
    print("Passed step 2...")

    for _ in range(10_000):
        P = MyCurve.random_element()
        Q = MyCurve.random_element()
        R = MyCurve.random_element()

        try:
            T1 = P + Q
            T2 = P + R
        except:
            print(":(")
            exit(1)

        if T1 == T2:
            print(":(")
            exit(1)
    print("Passed step 3...")

    for _ in range(100):
        P = MyCurve.random_element()
        k = random.randint(1, MyCurve.order - 1)
        l = MyCurve.order - k

        try:
            T1 = k * P
            T2 = l * P
            T3 = T1 + T2
        except:
            print(":(")
            exit(1)

        if T1 is None or T2 is None or T3 is not None:
            print(":(")
            exit(1)
    print("Passed step 4...")

    for _ in range(100):
        P = MyCurve.random_element()
        k = random.randint(1, MyCurve.order - 1)
        l = random.randint(1, MyCurve.order - 1)

        try:
            T1 = l * (k * P)
            T2 = k * (l * P)
        except:
            print(":(")
            exit(1)

        if T1 != T2:
            print(":(")
            exit(1)
    print("Passed step 5...")

    for _ in range(1_000):
        P = MyCurve.random_element()
        k = random.randint(3, 32)

        try:
            T1 = k * P
            T2 = P
            for _ in range(k - 1):
                T2 = T2 + P
        except:
            print(":(")
            exit(1)

        if T1 != T2:
            print(":(")
            exit(1)
    print("Passed step 6...")


def print_flag():
    with open("./flag", "r") as f:
        print(f"Flag is: {f.read()}")


def main():
    setup()
    test()
    print_flag()


if __name__ == "__main__":
    main()
