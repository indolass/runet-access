// Verdict for "did the public page really open in the browser?". Pure logic, unit-tested (page-verdict.test.mjs).
//
// Lesson that shaped it: the first real run called Gosuslugi "captcha" because (a) it looked at the page after
// only 4 s, when this single-page app still showed a skeleton (it needed ~30 s over the tunnel), and (b) the word
// "captcha" was found in the page SOURCE (script names), not on the screen. A captcha counts only if it is VISIBLE
// (a visible captcha/challenge element, or captcha wording in a SHORT visible text, as on an interstitial), and a
// still-changing page is "not rendered yet", not "blocked".

export const CAPTCHA_TEXT = /captcha|капч|я не робот|i'?m not a robot|are you (a )?human|подтвердите,? что вы (не робот|человек)|проверка (безопасности|браузера)|checking your browser|just a moment|attention required/i;
export const DENIED_TEXT = /access denied|forbidden|доступ (к сайту )?(запрещ|ограничен)|отказано в доступе|доступ закрыт|not available in your (country|region)|недоступен.*(вашего региона|вашей страны)|error 1020|403 forbidden/i;

// An interstitial is short. On a long content page the same words are ordinary content.
const SHORT_PAGE = 1500;

/**
 * @param {{url:string,title:string,text:string,textLen:number,visibleCaptchaElements:number,complete:boolean,stable:boolean}} i
 * @returns {{state:string, error?:string}}
 */
export function classifyPage(i) {
  const errCode = ((i.text || "").match(/ERR_[A-Z0-9_]+/) || [""])[0];
  if ((i.url || "").startsWith("chrome-error://") || errCode) return { state: "ошибка соединения", error: errCode || "страница ошибки Chrome" };
  if (!i.complete) return { state: "таймаут", error: "страница не загрузилась за лимит времени" };
  const shortText = i.textLen < SHORT_PAGE;
  if (i.visibleCaptchaElements > 0 || (shortText && CAPTCHA_TEXT.test(`${i.title} ${i.text}`))) return { state: "Критерий не пройден: капча" };
  if (DENIED_TEXT.test(i.title || "") || (shortText && DENIED_TEXT.test(i.text || ""))) return { state: "отказ сайта", error: "страница отказа в доступе" };
  if (i.textLen < 200) return i.stable ? { state: "пусто", error: "страница без видимого содержимого" } : { state: "не успела отрисоваться", error: "видимого содержимого мало и оно ещё менялось к концу ожидания" };
  return { state: "открылась" };
}

/** Runs inside the page: counts only elements the user can actually see. */
export const DOM_PROBE = `JSON.stringify((() => {
  const vis = (e) => { const r = e.getBoundingClientRect(); const cs = getComputedStyle(e); return r.width > 20 && r.height > 20 && cs.visibility !== 'hidden' && cs.display !== 'none'; };
  const cap = [...document.querySelectorAll('[class*="captcha" i],[id*="captcha" i],iframe[src*="captcha" i],iframe[src*="challenge" i]')].filter(vis).length;
  const t = document.body ? document.body.innerText : '';
  return { url: location.href, title: document.title, textLen: t.length, text: t.slice(0, 4000), visibleCaptchaElements: cap, readyState: document.readyState };
})())`;
