# Python Design Patterns

> 以 Python 示範常見的設計模式（Design Patterns）：**Singleton、Builder、Factory、Facade、Adapter、Strategy、Observer**。每節含概念重點、何時使用、與可直接貼上的程式碼範例。

---

## 目錄
- [Singleton（單例）](#singleton單例)
- [Builder（生成器）](#builder生成器)
- [Factory（工廠）](#factory工廠)
- [Facade（外觀）](#facade外觀)
- [Adapter（轉接器）](#adapter轉接器)
- [Strategy（策略）](#strategy策略)
- [Observer（觀察者）](#observer觀察者)
- [型別與測試 Tips（typing / unittest）](#型別與測試-tipstyping--unittest)
- [如何執行範例](#如何執行範例)

---

## Singleton（單例）

**重點：** 全系統只需要一個物件實例（例如：`Logger`、`Config`、`EventBus`）。  
**何時用：** 多個模組共用同一資源，避免「多個 new/實例」造成狀態不一致或檔案競爭。

```python
# ❌ Bad：同時建立多個 Logger，彼此搶寫同一檔案/串流
class LoggerBad:
    def __init__(self, name="app.log"):
        self.name = name
    def error(self, msg: str):
        print(f"[ERROR] {msg} -> {self.name}")

logger1 = LoggerBad()
logger2 = LoggerBad()  # 兩個 logger 都可能打到同一檔案

# ✅ Good：以 Singleton 確保只有一個實例
class Logger:
    _instance = None
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    def __init__(self, name: str = "app.log"):
        # 注意：__init__ 會在每次拿到實例時呼叫，但此例簡化處理
        self.name = name
    def info(self, msg: str):
        print(f"[INFO] {msg} -> {self.name}")
    def error(self, msg: str):
        print(f"[ERROR] {msg} -> {self.name}")

logger = Logger()              # 全域同一實例
logger.error("Failed to process payment")
```

> 補充：也可用 **metaclass** 或 **module-level singleton**（在模組載入時建立單一實例供匯入）。

---

## Builder（生成器）

**重點：** 以**流式（fluent）API** 建構複雜物件，避免大型 `__init__` 參數地獄。  
**何時用：** 物件擁有許多可選欄位、需要預設值與驗證。

```python
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Literal

HttpMethod = Literal["GET", "POST", "PUT", "DELETE"]

@dataclass(frozen=True)
class RequestOptions:
    url: str
    method: HttpMethod
    headers: Dict[str, str] = field(default_factory=dict)
    timeout: int = 10_000
    retries: int = 0
    body: Optional[Any] = None

class RequestBuilder:
    def __init__(self) -> None:
        self._url: Optional[str] = None
        self._method: Optional[HttpMethod] = None
        self._headers: Dict[str, str] = {}
        self._timeout: int = 10_000
        self._retries: int = 0
        self._body: Optional[Any] = None

    def set_url(self, url: str):
        self._url = url; return self
    def set_method(self, method: HttpMethod):
        self._method = method; return self
    def add_header(self, key: str, value: str):
        self._headers[key] = value; return self
    def set_timeout(self, ms: int):
        self._timeout = ms; return self
    def set_retries(self, n: int):
        self._retries = n; return self
    def set_body(self, body: Any):
        self._body = body; return self

    def build(self) -> RequestOptions:
        if not self._url or not self._method:
            raise ValueError("url 與 method 為必填")
        return RequestOptions(
            url=self._url,
            method=self._method,
            headers=dict(self._headers),
            timeout=self._timeout,
            retries=self._retries,
            body=self._body,
        )

# ✅ 使用範例
better_request = (
    RequestBuilder()
    .set_url("https://api.example.com")
    .set_method("POST")
    .add_header("Authorization", "Bearer token")
    .set_timeout(30_000)
    .set_retries(3)
    .set_body({ "name": "John" })
    .build()
)
```

---

## Factory（工廠）

**重點：** 將「建立何種具體類別」的判斷集中管理，**呼叫端只關注型別**。  
**何時用：** 依條件建立不同子類別、或希望**隔離 new/實例化 的散落**。

```python
from dataclasses import dataclass
from typing import Literal, Dict, Type

UserRole = Literal["admin", "moderator", "regular"]

@dataclass
class UserData:
    id: str
    name: str

class User:
    role: UserRole
    def __init__(self, data: UserData):
        self.data = data

class AdminUser(User):
    role: UserRole = "admin"

class ModeratorUser(User):
    role: UserRole = "moderator"

class RegularUser(User):
    role: UserRole = "regular"

class UserFactory:
    _map: Dict[UserRole, Type[User]] = {
        "admin": AdminUser,
        "moderator": ModeratorUser,
        "regular": RegularUser,
    }
    @classmethod
    def create(cls, role: UserRole, data: UserData) -> User:
        try:
            return cls._map[role](data)
        except KeyError as e:
            raise ValueError(f"Invalid user role: {role}") from e

# ✅ 乾淨作法
clean_user = UserFactory.create("admin", UserData(id="1", name="John"))

# ❌ 雜亂作法：分散的 if/elif/new，難以維護與測試
t = "admin"
d = UserData(id="1", name="John")
if t == "admin":
    user = AdminUser(d)
elif t == "moderator":
    user = ModeratorUser(d)
else:
    user = RegularUser(d)
```

---

## Facade（外觀）

**重點：** 對外提供**單一、簡潔**的 API，**隱藏多個子系統**的複雜互動。  
**何時用：** 呼叫流程跨多個服務（付款、庫存、物流、風控），希望調用端只打一行。

```python
from dataclasses import dataclass

@dataclass
class Product:
    id: str
    name: str
    price: float

@dataclass
class Address:
    city: str

class PaymentProcessor:
    def charge(self, user: User, amount: float) -> bool:
        print(f"Charging {user.data.name} amount={amount}")
        return True

class InventorySystem:
    def check_stock(self, product: Product) -> bool:
        print(f"Checking stock for {product.name}")
        return True
    def reserve(self, product: Product) -> None:
        print(f"Reserving {product.name}")

class ShippingCalculator:
    def compute(self, address: Address) -> float:
        print(f"Computing shipping for {address.city}")
        return 10.0

class FraudDetector:
    def verify(self, user: User) -> bool:
        print(f"Verifying {user.data.name}")
        return True

class OrderFacade:
    def __init__(self):
        self.payment = PaymentProcessor()
        self.inventory = InventorySystem()
        self.shipping = ShippingCalculator()
        self.fraud = FraudDetector()

    def place_order(self, user: User, product: Product, address: Address) -> bool:
        try:
            if not self.fraud.verify(user):
                raise RuntimeError("Fraud check failed")
            if not self.inventory.check_stock(product):
                raise RuntimeError("Product out of stock")
            shipping = self.shipping.compute(address)
            total = product.price + shipping
            if not self.payment.charge(user, total):
                raise RuntimeError("Payment failed")
            self.inventory.reserve(product)
            return True
        except Exception as e:
            print(f"[Order Error] {e}")
            return False

# ✅ 使用
order_system = OrderFacade()
order_system.place_order(clean_user, Product("p1", "Book", 20.0), Address("Taipei"))
```

---

## Adapter（轉接器）

**重點：** **轉換介面**，讓第三方 API 能以**我們系統期望的介面**使用。  
**何時用：** 套件回傳單位/命名不同、或 legacy 介面無法直接替換。

```python
from typing import Protocol

# 第三方 Weather API（假設不可改）
class WeatherAPI(Protocol):
    def get_temp_c(self) -> float: ...
    def get_humidity(self) -> int: ...
    def get_wind_speed_kph(self) -> float: ...

class ThirdPartyWeatherAPI:
    def get_temp_c(self) -> float:
        return 22.0
    def get_humidity(self) -> int:
        return 65
    def get_wind_speed_kph(self) -> float:
        return 15.0

# 我方系統期望的介面
class WeatherApp(Protocol):
    def get_temp_f(self) -> float: ...
    def get_humidity(self) -> int: ...
    def get_wind_speed_mph(self) -> float: ...

# ❌ 沒有 Adapter：到處都是零碎換算
raw = ThirdPartyWeatherAPI()
if raw.get_temp_c() * 9/5 + 32 > 75:
    print("It's hot!")
if raw.get_wind_speed_kph() * 0.621371 > 10:
    print("It's windy!")

# ✅ 有 Adapter：統一換算、呼叫端乾淨
class WeatherAdapter:
    def __init__(self, api: WeatherAPI):
        self._api = api
    def get_temp_f(self) -> float:
        return self._api.get_temp_c() * 9/5 + 32
    def get_humidity(self) -> int:
        return self._api.get_humidity()
    def get_wind_speed_mph(self) -> float:
        return self._api.get_wind_speed_kph() * 0.621371

weather = WeatherAdapter(ThirdPartyWeatherAPI())
if weather.get_temp_f() > 75:
    print("It's hot!")
if weather.get_wind_speed_mph() > 10:
    print("It's windy!")
```

---

## Strategy（策略）

**重點：** 把**可替換的演算法/行為**抽成獨立策略，於**執行期**自由切換。  
**何時用：** if/elif 針對「流程差異」越寫越長。

```python
from typing import Protocol

# ❌ 沒有 Strategy：if/elif 惡夢
class CommuterBad:
    def go_to_work(self, transport_type: str) -> None:
        if transport_type == "car":
            pass  # 車子的流程
        elif transport_type == "bus":
            pass  # 公車的流程
        elif transport_type == "bike":
            pass  # 單車的流程

# ✅ 有 Strategy
class TransportStrategy(Protocol):
    def transport(self) -> None: ...

class CarStrategy:
    def transport(self) -> None:
        print("Driving to work by car")

class BusStrategy:
    def transport(self) -> None:
        print("Taking the bus to work")

class BikeStrategy:
    def transport(self) -> None:
        print("Cycling to work")

class BetterCommuter:
    def __init__(self) -> None:
        self._strategy: TransportStrategy | None = None
    def set_strategy(self, strategy: TransportStrategy) -> None:
        self._strategy = strategy
    def go_to_work(self) -> None:
        if not self._strategy:
            raise RuntimeError("Transport strategy not set")
        self._strategy.transport()

# 使用
commuter = BetterCommuter()
commuter.set_strategy(CarStrategy())
commuter.go_to_work()
commuter.set_strategy(BikeStrategy())
commuter.go_to_work()
```

---

## Observer（觀察者）

**重點：** 透過**訂閱/通知**機制，主體（Subject）在狀態變化時**自動廣播**給觀察者（Observers）。  
**何時用：** `EventEmitter`、UI 狀態更新、資料流（推播）。

```python
from typing import Protocol, List

class Subscriber(Protocol):
    def update(self, video_title: str) -> None: ...

class BetterVideoChannel:
    def __init__(self) -> None:
        self._subs: List[Subscriber] = []
    def subscribe(self, sub: Subscriber) -> None:
        self._subs.append(sub)
    def unsubscribe(self, sub: Subscriber) -> None:
        try:
            self._subs.remove(sub)
        except ValueError:
            pass
    def upload_video(self, title: str) -> None:
        print(f"Uploading video: {title}")
        self._notify(title)
    def _notify(self, video_title: str) -> None:
        for s in list(self._subs):
            s.update(video_title)

# Demo Subscriber
class UserSubscriber:
    def __init__(self, name: str) -> None:
        self.name = name
    def update(self, video_title: str) -> None:
        print(f"{self.name} received: {video_title}")

# 使用
channel = BetterVideoChannel()
alice = UserSubscriber("Alice")
bob = UserSubscriber("Bob")
channel.subscribe(alice)
channel.subscribe(bob)
channel.upload_video("Design Patterns in Python")  # 兩人都會收到通知
```

---

## 型別與測試 Tips（typing / unittest）

- **善用 `typing` 與 `Protocol`**：為 `Strategy`、`Adapter`、`Observer` 先定義介面契約，再提供多個實作，利於測試替身（mocks）。
- **偏好 Composition over Inheritance**：`Facade` 與 `Strategy` 展現以組合達成擴充性的精神。
- **依賴注入（Dependency Injection）**：實務中將 `Facade` 內的子系統改為建構子注入，便於 mock 與單元測試。
- **dataclass + Immutable**：對不可變資料使用 `dataclass(frozen=True)` 以避免副作用。