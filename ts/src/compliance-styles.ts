/**
 * The compliance card's own stylesheet, trimmed to the sections this card
 * renders (summary, test results, findings, sessions drill-down via native
 * `<details>`, quality protocol, run info) and scoped under `.cc` on every
 * selector, so it can never leak onto, or be affected by, the verification
 * page or any other card on the same document.
 */
export const COMPLIANCE_CSS = `
.cc{--navy:#232F42;--gold:#E8A33D;--gold-l:#FBEFD9;--cream:#F6F2EA;--line:#E3DED3;--slate:#6B7482;--ink:#1F2733;--ok:#2E7D5B;--ok-l:#E3F1EA;--bad:#B5462F;--bad-l:#F8E6E1;--person:#5B4BA0;--person-l:#ECE8F7;--r:14px;
  font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Helvetica,Arial,sans-serif;color:var(--ink);background:#fff;display:block;max-width:1080px;margin:26px auto;padding:0 28px}
.cc *{box-sizing:border-box}
.cc h1,.cc h2,.cc h3{font-family:Georgia,"Iowan Old Style",Cambria,serif;color:var(--navy);margin:0}
.cc a{color:var(--navy);cursor:pointer}
.cc .hd{background:var(--navy);color:#fff;padding:28px 32px;border-radius:var(--r) var(--r) 0 0;margin-top:20px}
.cc .hd .kicker{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#C9CED6}
.cc .hd h1{color:#fff;font-size:28px;margin:6px 0 4px}
.cc .hd .sub{color:#DDE1E7;font-size:15px}
.cc section{padding:28px 32px;border:1px solid var(--line);border-top:0}
.cc section h2{font-size:21px;margin-bottom:10px}
.cc .lede{color:var(--slate);margin:0 0 16px;max-width:760px}
.cc table.grid{width:100%;border-collapse:collapse;font-size:14.5px}
.cc table.grid th{text-align:left;font-size:11.5px;letter-spacing:.05em;text-transform:uppercase;color:var(--slate);border-bottom:2px solid var(--navy);padding:8px 10px}
.cc table.grid td{border-bottom:1px solid var(--line);padding:10px;vertical-align:top}
.cc table.grid td.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.cc .kind{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px;text-transform:uppercase;letter-spacing:.03em}
.cc .kind.judged{background:var(--person-l);color:var(--person)}
.cc .kind.recomputed{background:#E6EEF6;color:#2B5A85}
.cc .kind.unstated{background:var(--cream);color:var(--slate)}
.cc .tx{margin:8px 0 4px;font-size:13px}
.cc .tx .turn{padding:3px 0;border-top:1px solid var(--line);white-space:pre-wrap}
.cc .tx code{font-size:12px;color:var(--slate)}
.cc .hd .na{color:var(--ink)}
.cc .st{font-weight:700;font-size:13px}
.cc .st.ok{color:var(--ok)}.cc .st.exc{color:var(--bad)}.cc .st.ne{color:#8A93A6}.cc .st.future{color:var(--gold)}
.cc .fnd{border:1px solid var(--line);border-radius:12px;padding:14px 18px;margin-bottom:12px}
.cc .fnd .fh{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:8px}
.cc .fnd .fh b{color:var(--navy)}
.cc .sev{font-size:11px;font-weight:700;padding:2px 9px;border-radius:99px;text-transform:uppercase}
.cc .sev.high{background:var(--bad-l);color:var(--bad)}
.cc .sev.medium{background:var(--gold-l);color:#8A6A2F}
.cc .sev.low{background:var(--ok-l);color:var(--ok)}
.cc .fnd table.fk{width:100%;font-size:14px}
.cc .fnd table.fk th{text-align:left;color:var(--slate);font-weight:600;width:140px;vertical-align:top;padding:4px 0}
.cc .fnd table.fk td{padding:4px 0}
.cc details{margin-top:8px;border:1px solid var(--line);border-radius:10px;padding:8px 14px}
.cc details > summary{cursor:pointer;color:var(--navy);font-weight:600;font-size:14px}
.cc details.session{margin:8px 0 0 16px}
.cc .sessrow{display:flex;gap:10px;align-items:center;padding:6px 0;font-size:14px}
.cc .sessrow code{font-size:12px;color:var(--slate)}
.cc .tk{display:inline-block;width:20px;height:20px;border-radius:6px;text-align:center;line-height:20px;font-size:12px;margin-left:3px}
.cc .tk.y{background:var(--ok-l);color:var(--ok)}.cc .tk.n{background:var(--bad-l);color:var(--bad)}.cc .tk.ne{background:#EDEFF2;color:#8A93A6}
.cc .ck{border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:8px 0;font-size:14px}
.cc .ck .h{display:flex;gap:8px;align-items:center;font-weight:700;color:var(--navy)}
.cc .ck .why{margin-top:4px;color:var(--ink)}
.cc .ck .ev{margin-top:4px;font-size:12px;color:var(--slate)}
.cc .ck .ev code{background:var(--cream);padding:1px 6px;border-radius:5px;margin-right:4px}
.cc .na{margin-top:16px;font-size:13px;color:var(--slate);background:var(--cream);border-radius:10px;padding:10px 14px}
.cc .ran{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.cc .ran .it{background:var(--cream);border-radius:10px;padding:10px 12px}
.cc .ran .k{font-size:12.5px;color:var(--slate)}
.cc .ran .v{font-weight:600;color:var(--navy);word-break:break-word;font-size:13.5px}
.cc .applic{font-size:13px;color:var(--slate)}
@media (max-width:760px){.cc .ran{grid-template-columns:1fr}}
`;
