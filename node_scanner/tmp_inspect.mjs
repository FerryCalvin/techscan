import Wappalyzer from 'wappalyzer';

const wappalyzer = new Wappalyzer({ debug: false, extended: true });

(async () => {
  try {
    await wappalyzer.init();
    const site = await wappalyzer.open('https://example.com');
    const res = await site.analyze();
    console.log(JSON.stringify(res, null, 2));
  } catch (err) {
    console.error(err);
  } finally {
    try {
      await wappalyzer.destroy();
    } catch (err) {
      console.error('destroy failed', err);
    }
  }
})();
