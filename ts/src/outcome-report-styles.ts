/**
 * The outcome-report card's own stylesheet, trimmed to the rules the
 * sections this card actually renders use (no modal, tabs or live-verify
 * button styling -- this card has none of those), and scoped
 * under one `.oi` class on every selector so it can never leak onto the rest of
 * the emitted page (the verification page, the generic Result page) or be
 * affected by it. Every custom property and base/body-level rule the design put
 * on `:root`/`*`/`body` is rewritten onto `.oi` itself, since this card's root
 * element stands in for the page body it would otherwise own.
 *
 * Inlined into a single `<style>` element by `renderOutcomeReportPage` --
 * no `<link>`, no external font, no external URL of any kind (view tests
 * assert zero `http(s)://` substrings and zero `link`/`img`/`script`/`iframe`
 * elements anywhere on the page).
 */
export const OUTCOME_REPORT_CSS = `
.oi{--navy:#232F42;--gold:#E8A33D;--gold-l:#FBEFD9;--cream:#F6F2EA;--line:#E3DED3;--slate:#6B7482;--ink:#1F2733;--ok:#2E7D5B;--ok-l:#E3F1EA;--bad:#B5462F;--bad-l:#F8E6E1;--person:#5B4BA0;--person-l:#ECE8F7;--r:14px;
  font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Helvetica,Arial,sans-serif;color:var(--ink);background:#EEF0F3;display:block}
.oi *{box-sizing:border-box}
.oi h1,.oi h2,.oi h3{font-family:Georgia,"Iowan Old Style",Cambria,serif;color:var(--navy);margin:0}
.oi a{color:var(--navy)}
.oi .sheet{background:#fff;max-width:1080px;margin:26px auto;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,.08),0 10px 30px rgba(0,0,0,.06);position:relative;overflow:hidden}
.oi .sheet .pad{padding:64px 72px 56px}
.oi .ih-row{display:flex;justify-content:space-between;align-items:flex-start;gap:40px;margin-bottom:48px}
.oi .ih-title{text-align:right}
.oi .ih-title .inv-title{font-size:28px}
.oi .inv-title{font-family:Georgia,serif;font-size:30px;color:var(--navy);margin:0}
.oi .inv-sub{color:var(--slate);font-size:14px;margin-top:4px}
.oi .party .k{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--slate);margin-bottom:6px;font-weight:700;color:var(--navy)}
.oi .party .v{font-weight:600;color:var(--navy);font-size:16px}
.oi .party .d{font-size:14px;color:var(--slate);line-height:1.7;margin-top:4px}
.oi .meta{width:320px;flex:none;font-size:14px}
.oi .meta div{display:grid;grid-template-columns:130px 1fr}
.oi .meta span:first-child{color:var(--slate)}
.oi .meta span:last-child{text-align:right;word-break:break-all;min-width:0}
.oi .meta code{font-size:12.5px}
.oi table.lines{width:100%;border-collapse:collapse;margin-top:40px;font-size:14.5px}
.oi table.lines th{text-align:left;font-size:11.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--slate);border-bottom:2px solid var(--navy);padding:8px 10px}
.oi table.lines td{border-bottom:1px solid var(--line);padding:16px 10px;vertical-align:top}
.oi table.lines td.n,.oi table.lines th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.oi table.lines .desc b{color:var(--navy)}
.oi table.lines .desc small{display:block;color:var(--slate);font-size:12.5px}
.oi table.lines .src{font-size:11.5px;color:var(--slate);white-space:normal}
.oi .notes{font-size:13px;color:var(--slate);margin-top:44px;max-width:640px}
.oi .notes p{margin:0 0 8px;font-size:14px;color:var(--ink)}
.oi .notes .nh{font-size:11.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--slate);margin-bottom:6px}
.oi .stamps.inl{display:flex;flex-direction:row;align-items:center;justify-content:flex-start;margin-top:24px;gap:14px}
.oi .stamp{border:3px solid;border-radius:8px;padding:6px 12px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;font-size:13px;transform:rotate(-6deg)}
.oi .stamp.rec{color:var(--ok);border-color:var(--ok)}
.oi .stamp.hollow{color:#9AA1AC;border:3px dashed #BFC4CC;transform:rotate(-3deg);font-size:11.5px}
.oi .stamp small{display:block;font-weight:600;letter-spacing:0;text-transform:none;font-size:11px}
.oi .tamper-note{margin-top:24px;padding:14px 16px;border:1px solid var(--line);border-radius:12px;background:#FAF8F4;font-size:13.5px;color:var(--slate)}
.oi .sec{background:#fff;max-width:1080px;margin:0 auto 22px;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,.06);padding:30px 42px}
.oi .sec h2{font-size:22px}
.oi .sec .lede{color:var(--slate);margin:6px 0 16px}
.oi .cal{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:8px}
.oi .day{border:1px solid var(--line);border-radius:10px;padding:8px 9px;min-height:84px;background:#fff;position:relative}
.oi .day .dn{font-size:12px;color:var(--slate)}
.oi .day .v{font-weight:700;font-size:17px;color:var(--navy);font-variant-numeric:tabular-nums}
.oi .day .v small{font-weight:400;color:var(--slate);font-size:12px}
.oi .day .amt{font-size:11px;color:var(--slate);font-variant-numeric:tabular-nums}
.oi .mini{height:6px;border-radius:99px;background:var(--bad-l);overflow:hidden;margin-top:6px}
.oi .mini i{display:block;height:100%;background:var(--ok)}
.oi .day .sealed{font-size:11px;color:var(--slate);margin-top:6px}
.oi .day .src-says{display:inline-block;font-size:10.5px;font-weight:700;color:var(--navy);background:var(--gold-l);border:1px solid var(--gold);border-radius:999px;padding:0 6px;margin-top:2px}
.oi .day .tz{font-size:11px;color:var(--bad);margin-top:2px}
.oi p.date-note{font-size:13.5px;color:var(--ink);background:#FAF8F4;border:1px solid var(--line);border-left:4px solid var(--gold);border-radius:8px;padding:10px 14px;margin:14px 0 0}
.oi .sec p.date-note{margin:0 0 14px}
.oi .flag{position:absolute;top:7px;right:8px;font-size:11px;color:var(--gold)}
.oi .flag:before{content:"";display:inline-block;width:6px;height:6px;margin-right:5px;background:var(--gold);transform:rotate(45deg);vertical-align:1px}
.oi .legend{display:flex;gap:18px;flex-wrap:wrap;font-size:13px;color:var(--slate);margin-top:12px}
.oi .legend span i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:-1px}
.oi .hc-top{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:14px}
.oi .hc-top div{padding:12px 14px;border-right:1px solid var(--line)}
.oi .hc-top div:last-child{border-right:0}
.oi .hc-top b{display:block;font-size:22px;color:var(--navy);font-variant-numeric:tabular-nums}
.oi .hc-top span{font-size:12.5px;color:var(--slate)}
.oi table.hct{width:100%;border-collapse:collapse;font-size:14px}
.oi table.hct th{text-align:left;font-size:11.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--slate);border-bottom:2px solid var(--navy);padding:7px 10px}
.oi table.hct td{padding:9px 10px;border-bottom:1px solid var(--line);font-variant-numeric:tabular-nums}
.oi table.hct .n{text-align:right}
.oi .bars{display:grid;gap:12px;margin-bottom:26px}
.oi .bar{display:grid;grid-template-columns:260px 1fr 190px;gap:16px;align-items:center;padding:12px 16px;border:1px solid var(--line);border-radius:12px;background:#fff}
.oi .bar .nm{font-weight:600;color:var(--navy)}
.oi .track{height:14px;background:var(--bad-l);border-radius:99px;overflow:hidden}
.oi .track i{display:block;height:100%;background:var(--ok);border-radius:99px}
.oi .bar .num{text-align:right;font-variant-numeric:tabular-nums;font-size:15px}
.oi .reasons{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
.oi .rsn{display:flex;justify-content:space-between;gap:12px;padding:10px 14px;background:var(--bad-l);border-radius:10px;font-size:15px}
.oi .rsn .c{font-weight:700;color:var(--bad);font-variant-numeric:tabular-nums}
.oi h3{font-size:19px;margin:26px 0 12px}
.oi .pack{display:grid;grid-template-columns:repeat(3,1fr);gap:0;border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:14px}
.oi .pk{padding:10px 14px;border-right:1px solid var(--line);border-bottom:1px solid var(--line)}
.oi .pk:nth-child(3n){border-right:0}
.oi .pk .k{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--slate)}
.oi .pk .v{color:var(--navy);font-weight:600;font-size:14px}
.oi .outcome{border:2px solid var(--navy);border-radius:var(--r);padding:18px 20px;margin-bottom:14px;display:flex;gap:16px;align-items:center}
.oi .outcome .t{font-size:13px;color:var(--slate);text-transform:uppercase;letter-spacing:.06em}
.oi .outcome .v{font-family:Georgia,Cambria,serif;font-size:22px;color:var(--navy)}
.oi .checks{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.oi .check{border:1px solid var(--line);border-radius:var(--r);padding:16px 18px;background:#fff}
.oi .check .ic{width:34px;height:34px;border-radius:10px;background:var(--gold-l);color:var(--navy);display:grid;place-items:center;margin-bottom:8px}
.oi .outcome .oic{width:40px;height:40px;flex:none;border-radius:10px;background:var(--gold-l);color:var(--navy);display:grid;place-items:center}
.oi svg{display:block}
.oi .check .q{font-weight:700;color:var(--navy);font-size:17px}
.oi .check .d{color:var(--slate);font-size:14px;margin-top:4px}
.oi ul.subs{list-style:none;padding:0;margin:10px 0 0;border-top:1px solid var(--line)}
.oi ul.subs li{padding:6px 0;border-bottom:1px dashed var(--line);font-size:12.5px}
.oi ul.subs li b{display:block;color:var(--navy);font-size:13px}
.oi ul.subs li b:before{content:"";display:inline-block;width:5px;height:5px;margin-right:6px;border:1.5px solid var(--gold);border-radius:50%;vertical-align:2px}
.oi ul.subs li span{color:var(--slate)}
.oi .rule{margin-top:14px;font-size:14px;color:var(--slate)}
.oi .rule b{color:var(--ink)}
.oi .ran{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.oi .ran .it{background:var(--cream);border-radius:12px;padding:12px 14px}
.oi .ran .k{font-size:13px;color:var(--slate)}
.oi .ran .v{font-weight:600;color:var(--navy);word-break:break-word}
.oi .ran .v code{font-size:13px}
.oi .lock{margin-top:12px;font-size:14px;color:var(--slate)}
.oi .tech{display:grid;grid-template-columns:150px 1fr;gap:6px 14px;margin-top:12px;font-size:13px}
.oi .tech .k{color:var(--slate)}
.oi .tech .v{font-family:ui-monospace,Menlo,monospace;word-break:break-all;min-width:0}
.oi .note{font-size:13px;color:var(--slate);margin-top:12px}
.oi.oi-banner{max-width:1080px;margin:26px auto 0;padding:12px 18px;border-radius:6px;font-weight:700;font-size:15px;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.oi.oi-banner-ok{background:var(--ok-l);color:var(--ok);border:1px solid var(--ok)}
.oi.oi-banner-incomplete{background:var(--gold-l);color:var(--ink);border:1px solid var(--gold)}
.oi.oi-banner-failed{background:var(--bad-l);color:var(--bad);border:1px solid var(--bad)}
.oi.oi-vp{padding:0 0 26px}
.oi.oi-vp .sec{margin-bottom:0}
.oi.oi-vp h4{font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--slate);margin:22px 0 8px;padding-top:14px;border-top:1px solid var(--line)}
.oi.oi-vp h2 + dl{margin-top:14px}
.oi.oi-vp dl{display:grid;grid-template-columns:150px 1fr;gap:6px 14px;margin:0;font-size:13px}
.oi.oi-vp dt{color:var(--slate)}
.oi.oi-vp dd{margin:0;font-family:ui-monospace,Menlo,monospace;word-break:break-all;color:var(--navy)}
.oi.oi-vp p{font-size:14px;margin:6px 0}
.oi.oi-vp ul,.oi.oi-vp ol{margin:6px 0;padding-left:22px;font-size:14px}
.oi.oi-vp li{padding:2px 0}
.oi.oi-vp ol li strong{color:var(--navy)}
.oi.oi-vp [data-check-status="pass"] span,.oi.oi-vp [data-check-status="passed"] span{color:var(--ok)}
.oi.oi-vp details{margin-top:8px;font-size:13px}
.oi.oi-vp summary{cursor:pointer;color:var(--navy);font-weight:600}
.oi.oi-vp details ul{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all;max-height:420px;overflow:auto}
.oi.oi-vp .seal-checkpointed{color:var(--ok)}
.oi.oi-vp .seal-uncheckpointed,.oi.oi-vp .seal-membership_invalid{color:var(--bad)}
.oi.oi-vp > .sec > p:last-child{margin-top:18px;padding:12px 14px;border-radius:10px;background:var(--cream);color:var(--slate)}
.oi details.drill{margin-top:8px}
.oi details.drill > summary{cursor:pointer;color:var(--navy);font-size:13px;font-weight:600;list-style:none}
.oi details.drill > summary::-webkit-details-marker,.oi summary.rsn::-webkit-details-marker,.oi summary.conv-s::-webkit-details-marker{display:none}
.oi details.drill[open] > summary{margin-bottom:8px}
.oi .reasons details.rsn-d[open]{grid-column:1/-1}
.oi summary.rsn{cursor:pointer;list-style:none}
.oi summary.rsn .c{white-space:nowrap}
.oi details.rsn-d > .convs{margin-top:8px}
.oi .convs{display:grid;gap:6px}
.oi details.conv{border:1px solid var(--line);border-radius:10px;background:#fff}
.oi details.conv[open]{border-color:var(--navy);box-shadow:0 1px 6px rgba(0,0,0,.06)}
.oi summary.conv-s{cursor:pointer;list-style:none;display:grid;grid-template-columns:76px 86px 1fr auto;gap:10px;align-items:center;padding:8px 12px;font-size:13.5px;font-weight:400}
.oi summary.conv-s .cid{font-weight:700;color:var(--navy)}
.oi summary.conv-s .cwhy{color:var(--slate)}
.oi summary.conv-s .go{color:var(--navy);font-weight:600;white-space:nowrap}
.oi .pill{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:700;white-space:nowrap;text-align:center}
.oi .pill.ok{background:var(--ok-l);color:var(--ok)}
.oi .pill.bad{background:var(--bad-l);color:var(--bad)}
.oi .pill.na{background:#EEF0F3;color:var(--slate);border:1px dashed #BFC4CC}
.oi .pill.ne{background:var(--gold-l);color:#8A5A12}
.oi .conv-b{padding:4px 16px 16px;border-top:1px solid var(--line);font-size:13.5px;font-weight:400;color:var(--ink)}
.oi .conv-b h4{font-size:11.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--slate);margin:16px 0 6px}
.oi .conv-b .small{font-size:12.5px;color:var(--slate);margin:6px 0}
.oi .conv-b .muted{color:var(--slate)}
.oi .conv-b .absent{margin:0;padding:10px 12px;border:1px dashed #BFC4CC;border-radius:10px;background:#FAF8F4;color:var(--slate);word-break:break-word}
.oi .tscroll{overflow-x:auto}
.oi table.crit{width:100%;border-collapse:collapse;margin:0;font-size:12.5px}
.oi table.lines table.crit th,.oi table.crit th{text-align:left;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--slate);border-bottom:1px solid var(--navy);padding:5px 8px}
.oi table.lines table.crit td,.oi table.crit td{border-bottom:1px solid var(--line);padding:7px 8px;vertical-align:top}
.oi table.crit td.cn{width:30%}
.oi table.crit td.cn b{display:block;color:var(--navy);font-size:13px}
.oi table.crit td.cn small{display:block;color:var(--slate);font-size:11.5px}
.oi small.wsrc{display:block;font-style:italic;color:var(--slate);font-size:11px;margin-top:2px}
.oi .pnote{max-width:1080px;margin:26px auto 0;box-sizing:border-box;background:var(--gold-l);border:1px solid var(--gold);border-left:6px solid var(--gold);border-radius:6px;padding:18px 26px}
.oi .pnote .pn-k{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--slate);font-weight:700}
.oi .pnote .pn-t{font-size:20px;color:var(--navy);margin:4px 0 8px}
.oi .pnote .pn-l{margin:0;padding-left:20px;font-size:14.5px;line-height:1.55}
.oi .pnote .pn-l li{margin:4px 0}
.oi .pnote .pn-src{font-size:12px;color:var(--slate);margin:10px 0 0;font-style:italic}
.oi span.edited{display:inline-block;margin-left:8px;padding:1px 7px;border-radius:999px;background:var(--gold-l);border:1px solid var(--gold);color:var(--navy);font-size:10.5px;font-weight:700;letter-spacing:.03em;vertical-align:1px;white-space:nowrap}
.oi p[data-wording-note]{font-size:12.5px;color:var(--slate);margin:10px 0}
.oi table.crit td.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.oi table.crit td.rat code{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--slate);word-break:break-word;white-space:normal}
.oi ul.why{margin:0;padding-left:20px}
.oi ul.why li{padding:2px 0}
.oi dl.chk{display:grid;grid-template-columns:190px 1fr;gap:4px 12px;margin:0;font-size:12px}
.oi dl.chk dt{color:var(--slate)}
.oi dl.chk dd{margin:0;font-family:ui-monospace,Menlo,monospace;word-break:break-all;color:var(--navy)}
.oi ol.turns{list-style:none;margin:6px 0 0;padding:0;display:grid;gap:6px;max-height:560px;overflow:auto;border:1px solid var(--line);border-radius:10px;padding:10px;background:#FAF8F4}
.oi li.turn{border-radius:10px;padding:6px 10px;max-width:88%;background:#fff;border:1px solid var(--line)}
.oi li.turn.user{justify-self:end;background:var(--person-l);border-color:transparent}
.oi li.turn.assistant{justify-self:start}
.oi li.turn.tool{justify-self:center;max-width:96%;border-style:dashed}
.oi li.turn .who{font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--slate)}
.oi li.turn .say{white-space:pre-wrap;word-break:break-word}
.oi li.turn pre{margin:4px 0 0;font-family:ui-monospace,Menlo,monospace;font-size:11px;white-space:pre-wrap;word-break:break-all;max-height:160px;overflow:auto;color:var(--slate)}
.oi li.turn pre.call{color:var(--navy);background:var(--gold-l);padding:3px 6px;border-radius:6px}
@media (max-width:820px){
  .oi .ih-row{grid-template-columns:1fr}
  .oi .ih-title{text-align:left}
  .oi .meta{width:100%}
  .oi .sheet .pad,.oi .sec{padding:22px}
  .oi .hc-top{grid-template-columns:1fr 1fr}
}
@media (max-width:760px){
  .oi .checks,.oi .ran,.oi .reasons{grid-template-columns:1fr}
  .oi .bar{grid-template-columns:1fr}
  .oi .bar .num{text-align:left}
  .oi .cal{grid-template-columns:repeat(7,1fr)}
  .oi .day{min-height:64px;padding:6px}
  .oi .day .v{font-size:14px}
  .oi .tech,.oi.oi-vp dl,.oi dl.chk{grid-template-columns:1fr}
  .oi summary.conv-s{grid-template-columns:1fr auto}
}
@media print{
  .oi{background:#fff}
  .oi .sheet,.oi .sec{box-shadow:none;margin:0 0 12px}
}
`;
