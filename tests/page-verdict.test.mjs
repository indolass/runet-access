// Run: node --test tests/page-verdict.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyPage } from "./page-verdict.mjs";

const base = { url: "https://www.example.gov/", title: "Портал", text: "", textLen: 0, visibleCaptchaElements: 0, complete: true, stable: true };
const page = (o) => classifyPage({ ...base, ...o });
const long = "Содержательный текст страницы. ".repeat(100); // ~3100 chars

test("REGRESSION: a skeleton that is still rendering is not a captcha and not a success", () => {
  // what the first real run saw on Gosuslugi after 4 s: 111 characters, nothing captcha-like on screen
  const r = page({ title: "Портал государственных услуг Российской Федерации", text: "Каталог Войти", textLen: 111, stable: false });
  assert.notEqual(r.state, "Критерий не пройден: капча");
  assert.equal(r.state, "не успела отрисоваться");
});

test("REGRESSION: the word 'captcha' in the page source must not matter (only what is visible does)", () => {
  // the source is not part of the verdict input at all; a page with normal visible text and no visible captcha opens
  assert.equal(page({ text: long, textLen: long.length }).state, "открылась");
});

test("a visible captcha element is a captcha, whatever the text length", () => {
  assert.equal(page({ text: long, textLen: long.length, visibleCaptchaElements: 1 }).state, "Критерий не пройден: капча");
});

test("captcha wording on a SHORT page (an interstitial) is a captcha", () => {
  for (const t of ["Подтвердите, что вы не робот", "Проверка безопасности браузера", "Just a moment...", "Введите символы с картинки (captcha)"]) {
    assert.equal(page({ text: t, textLen: t.length }).state, "Критерий не пройден: капча", t);
  }
});

test("captcha wording inside a LONG content page is ordinary content, not a captcha", () => {
  const t = long + " Новости: как защититься от капчи и ботов. ";
  assert.equal(page({ text: t, textLen: t.length }).state, "открылась");
});

test("denial pages: short denial text or a denial title", () => {
  assert.equal(page({ text: "Доступ к сайту ограничен", textLen: 24 }).state, "отказ сайта");
  assert.equal(page({ title: "403 Forbidden", text: long, textLen: long.length }).state, "отказ сайта");
  const news = long + " В новостях: сайт заблокирован по решению суда. ";
  assert.equal(page({ text: news, textLen: news.length }).state, "открылась");
});

test("not finished loading is a timeout; Chrome error pages are connection errors", () => {
  assert.equal(page({ complete: false }).state, "таймаут");
  assert.equal(page({ url: "chrome-error://chromewebdata/" }).state, "ошибка соединения");
  assert.equal(page({ text: "This site can’t be reached ERR_CONNECTION_RESET", textLen: 50 }).error, "ERR_CONNECTION_RESET");
});

test("stable but empty page is 'empty', a normal page with enough visible text opens", () => {
  assert.equal(page({ textLen: 20, text: "x" }).state, "пусто");
  assert.equal(page({ text: long, textLen: long.length }).state, "открылась");
});

test("REGRESSION: a page whose document is shown (interactive) but has a stuck image still opens", () => {
  // nalog.gov.ru: HTTP 200, 4500+ visible characters, no captcha, readyState stayed 'interactive' because the
  // image host kept resetting HTTP/2 streams. The caller passes complete=true once the document is parsed.
  assert.equal(page({ title: "Федеральная налоговая служба", text: long + long + long, textLen: 4530 }).state, "открылась");
});
