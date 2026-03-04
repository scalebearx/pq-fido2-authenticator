# TypeScript Design Patterns

> 以 TypeScript 示範常見的設計模式（Design Patterns）：**Singleton、Builder、Factory、Facade、Adapter、Strategy、Observer**。每節含概念重點、何時使用、與可直接貼上的程式碼範例。

---

## 目錄
- [Singleton（單例）](#singleton單例)
- [Builder（生成器）](#builder生成器)
- [Factory（工廠）](#factory工廠)
- [Facade（外觀）](#facade外觀)
- [Adapter（轉接器）](#adapter轉接器)
- [Strategy（策略）](#strategy策略)
- [Observer（觀察者）](#observer觀察者)
- [型別安全 Tips（TypeScript）](#型別安全-tipstypescript)
- [如何執行範例](#如何執行範例)

---

## Singleton（單例）

**重點：** 全系統只需要一個物件實例（例如：`Logger`、`Config`、`EventBus`）。
**何時用：** 多個模組共用同一資源，避免「多個 new 造成狀態不一致或檔案競爭」。

```ts
// ❌ Bad：同時建立多個 Logger，彼此搶寫同一檔案/串流
const logger1 = new Logger();
const logger2 = new Logger();

// ✅ Good：所有人只拿同一個實例
class Logger {
  private static instance: Logger;
  private constructor() {}
  static getInstance(): Logger {
    if (!Logger.instance) Logger.instance = new Logger();
    return Logger.instance;
  }
  info(msg: string)  { console.log(`[INFO] ${msg}`); }
  error(msg: string) { console.error(`[ERROR] ${msg}`); }
}

const logger = Logger.getInstance();
logger.error("Failed to process payment");
```

---

## Builder（生成器）

**重點：** 以**流式（fluent）API** 建構複雜物件，避免大型 constructor 參數地獄。
**何時用：** 物件擁有許多可選欄位、需要預設值與驗證。

```ts
type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";

interface RequestOptions {
  url: string;
  method: HttpMethod;
  headers?: Record<string, string>;
  timeout?: number;
  retries?: number;
  body?: unknown;
}

class RequestBuilder {
  private options: Partial<RequestOptions> = {};

  setURL(url: string) { this.options.url = url; return this; }
  setMethod(method: HttpMethod) { this.options.method = method; return this; }
  addHeader(key: string, value: string) {
    this.options.headers = { ...(this.options.headers ?? {}), [key]: value };
    return this;
  }
  setTimeout(ms: number) { this.options.timeout = ms; return this; }
  setRetries(n: number) { this.options.retries = n; return this; }
  setBody(body: unknown) { this.options.body = body; return this; }

  build(): RequestOptions {
    const { url, method } = this.options;
    if (!url || !method) throw new Error("url 和 method 為必填");
    return {
      url,
      method,
      headers: this.options.headers ?? {},
      timeout: this.options.timeout ?? 10_000,
      retries: this.options.retries ?? 0,
      body: this.options.body,
    };
  }
}

// ✅ 使用範例
const betterRequest = new RequestBuilder()
  .setURL("https://api.example.com")
  .setMethod("POST")
  .addHeader("Authorization", "Bearer token")
  .setTimeout(30_000)
  .setRetries(3)
  .setBody({ name: "John" })
  .build();
```

---

## Factory（工廠）

**重點：** 將「建立何種具體類別」的判斷集中管理，**呼叫端只關注型別**。
**何時用：** 依條件建立不同子類別、或希望**隔離 new 的散落**。

```ts
interface UserData { id: string; name: string; }

type UserRole = "admin" | "moderator" | "regular";

interface User {
  role: UserRole;
  data: UserData;
}

class AdminUser implements User {
  role: UserRole = "admin";
  constructor(public data: UserData) {}
}
class ModeratorUser implements User {
  role: UserRole = "moderator";
  constructor(public data: UserData) {}
}
class RegularUser implements User {
  role: UserRole = "regular";
  constructor(public data: UserData) {}
}

class UserFactory {
  static create(type: UserRole, data: UserData): User {
    switch (type) {
      case "admin": return new AdminUser(data);
      case "moderator": return new ModeratorUser(data);
      case "regular": return new RegularUser(data);
      default: {
        // TypeScript 技巧：讓未覆蓋分支在編譯期報錯
        const _exhaustiveCheck: never = type as never;
        throw new Error(`Invalid user type: ${_exhaustiveCheck}`);
      }
    }
  }
}

// ✅ 乾淨作法
const cleanUser = UserFactory.create("admin", { id: "1", name: "John" });

// ❌ 雜亂作法：分散的 if/else/new，難以維護與測試
const type = "admin";
const data = { id: "1", name: "John" };
let user: User;
if (type === "admin") user = new AdminUser(data);
else if (type === "moderator") user = new ModeratorUser(data);
else user = new RegularUser(data);
```

---

## Facade（外觀）

**重點：** 對外提供**單一、簡潔**的 API，**隱藏多個子系統**的複雜互動。
**何時用：** 呼叫流程跨多個服務（付款、庫存、物流、風控），希望調用端只打一行。

```ts
// 預設資料結構與子系統（實務上會改為真正實作或注入）
interface Product { id: string; name: string; price: number; }
interface Address { city: string; }

class PaymentProcessor { charge(_user: User, _amount: number) { return true; } }
class InventorySystem { checkStock(_product: Product) { return true; } reserve(_product: Product) {} }
class ShippingCalculator { compute(_address: Address) { return 10; } }
class FraudDetector { verify(_user: User) { return true; } }

class OrderFacade {
  private paymentProcessor = new PaymentProcessor();
  private inventorySystem = new InventorySystem();
  private shippingCalculator = new ShippingCalculator();
  private fraudChecker = new FraudDetector();

  placeOrder(user: User, product: Product, address: Address): boolean {
    try {
      if (!this.fraudChecker.verify(user)) throw new Error("Fraud check failed");
      if (!this.inventorySystem.checkStock(product)) throw new Error("Product out of stock");
      const shipping = constNumber(this.shippingCalculator.compute(address));
      const total = product.price + shipping;
      if (!this.paymentProcessor.charge(user, total)) throw new Error("Payment failed");
      this.inventorySystem.reserve(product);
      return true;
    } catch (error) {
      console.error(error);
      return false;
    }
  }
}
function constNumber(n: number) { return n; } // 僅為完整性示範

// ✅ 使用：呼叫端一行搞定
const orderSystem = new OrderFacade();
orderSystem.placeOrder(cleanUser, { id: "p1", name: "Book", price: 20 }, { city: "Taipei" });
```

---

## Adapter（轉接器）

**重點：** **轉換介面**，讓第三方 API 能以**我們系統期望的介面**使用。
**何時用：** 套件回傳單位/命名不同、或 legacy 介面無法直接替換。

```ts
// 第三方 Weather API
interface WeatherAPI {
  getTempC(): number;
  getHumidity(): number;
  getWindSpeedKPH(): number;
}

// 我方系統期望的介面
interface WeatherApp {
  getTempF(): number;
  getHumidity(): number;
  getWindSpeedMPH(): number;
}

class ThirdPartyWeatherAPI implements WeatherAPI {
  getTempC() { return 22; }
  getHumidity() { return 65; }
  getWindSpeedKPH() { return 15; }
}

// ❌ 沒有 Adapter：到處都是零碎換算
const raw = new ThirdPartyWeatherAPI();
if (raw.getTempC() * 9/5 + 32 > 75) console.log("It's hot!");
if (raw.getWindSpeedKPH() * 0.621371 > 10) console.log("It's windy!");

// ✅ 有 Adapter：統一換算、呼叫端乾淨
class WeatherAdapter implements WeatherApp {
  constructor(private weatherAPI: WeatherAPI) {}
  getTempF() { return this.weatherAPI.getTempC() * 9/5 + 32; }
  getHumidity() { return this.weatherAPI.getHumidity(); }
  getWindSpeedMPH() { return this.weatherAPI.getWindSpeedKPH() * 0.621371; }
}

const weather = new WeatherAdapter(new ThirdPartyWeatherAPI());
if (weather.getTempF() > 75) console.log("It's hot!");
if (weather.getWindSpeedMPH() > 10) console.log("It's windy!");
```

---

## Strategy（策略）

**重點：** 把**可替換的演算法/行為**抽成獨立策略，於**執行期**自由切換。
**何時用：** if/else 針對「流程差異」越寫越長。

```ts
// ❌ 沒有 Strategy：if/else 惡夢
class CommuterBad {
  goToWork(transportType: string) {
    if (transportType === "car") {
      /* ... */
    } else if (transportType === "bus") {
      /* ... */
    } else if (transportType === "bike") {
      /* ... */
    }
  }
}

// ✅ 有 Strategy
interface TransportStrategy {
  transport(): void;
}

class CarStrategy implements TransportStrategy {
  transport() { console.log("Driving to work by car"); /* car-specific */ }
}
class BusStrategy implements TransportStrategy {
  transport() { console.log("Taking the bus to work"); /* bus-specific */ }
}
class BikeStrategy implements TransportStrategy {
  transport() { console.log("Cycling to work"); /* bike-specific */ }
}

class BetterCommuter {
  private strategy?: TransportStrategy;
  setStrategy(strategy: TransportStrategy) { this.strategy = strategy; }
  goToWork() {
    if (!this.strategy) throw new Error("Transport strategy not set");
    this.strategy.transport();
  }
}

// 使用
const commuter = new BetterCommuter();
commuter.setStrategy(new CarStrategy());
commuter.goToWork();
commuter.setStrategy(new BikeStrategy());
commuter.goToWork();
```

---

## Observer（觀察者）

**重點：** 透過**訂閱/通知**機制，主體（Subject）在狀態變化時**自動廣播**給觀察者（Observers）。
**何時用：** `EventEmitter`、UI 狀態更新、資料流（推播）。

```ts
interface Subscriber {
  update(videoTitle: string): void;
}

class BetterVideoChannel {
  private subscribers: Subscriber[] = [];

  subscribe(subscriber: Subscriber) { this.subscribers.push(subscriber); }
  unsubscribe(subscriber: Subscriber) {
    const idx = this.subscribers.indexOf(subscriber);
    if (idx !== -1) this.subscribers.splice(idx, 1);
  }

  uploadVideo(title: string) {
    console.log(`Uploading video: ${title}`);
    this.notify(title);
  }

  private notify(videoTitle: string) {
    this.subscribers.forEach(sub => sub.update(videoTitle));
  }
}

// Demo Subscriber
class UserSubscriber implements Subscriber {
  constructor(private name: string) {}
  update(videoTitle: string) {
    console.log(`${this.name} received: ${videoTitle}`);
  }
}

// 使用
const channel = new BetterVideoChannel();
const alice = new UserSubscriber("Alice");
const bob = new UserSubscriber("Bob");

channel.subscribe(alice);
channel.subscribe(bob);
channel.uploadVideo("Design Patterns in TS"); // 兩人都會收到通知
```

---

## 型別安全 Tips（TypeScript）

- **使用 union + exhaustive check**：搭配 `never` 讓 Factory/Reducer 漏掉分支時在編譯期爆紅。
- **以 interface 描述抽象**：`Strategy`、`Adapter`、`Observer` 都先定義「契約」，再提供多個實作。
- **偏好 Composition over Inheritance**：`Facade` 與 `Strategy` 展現以組合達成擴充性的精神。
- **依賴注入（Dependency Injection）**：在實務中把 `Facade` 內的子系統改成建構子注入，利於測試。
