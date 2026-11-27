"""Dashboard analítico em um único HTML (sem dependências externas: ECharts embutido)."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .consolidar import ERROS, GLOSSARIO

STATIC = Path(__file__).parent / "static" / "echarts.min.js"


def gerar(d: dict, mascara) -> str:
    inv = d["inv"]
    tz = ZoneInfo(inv["fuso"])

    def dt(ms):
        return datetime.fromtimestamp(ms / 1000, tz).strftime("%Y-%m-%dT%H:%M:%S") if ms else None

    evs = [{"t": e["time_ms"], "i": e["instancia"], "r": e["realm"], "u": mascara(e["username"]),
            "y": e["type"], "c": e["client_id"], "ip": e["ip"], "s": e["session_id"], "er": e["error"],
            "d": {k: mascara(str(v)) for k, v in (e["details"] or {}).items()}, "id": e["id"]}
           for e in d["eventos"]]
    cob = [{"i": c["instancia"], "r": c["realm"], "u": mascara(c["username"]) if c["username"] else None,
            "cl": c["classe"], "st": c["status"], "de": mascara(c["detalhe"]), "ac": c["acao"],
            "desde": c["desde_ms"], "conta": c["conta_id"] is not None} for c in d["cobertura"]]
    contas = [{"i": c["instancia"], "r": c["realm"], "u": mascara(c["username"]), "id": c["user_id"],
               "via": c["via"], "origem": c["origem"], "hab": c["habilitada"],
               "criado": dt(c["criado_ms"]), "inc": c["incluida"]} for c in d["contas"]]
    extras = [{"tipo": x["tipo"], "i": x["instancia"], "r": x["realm"], "u": mascara(x["username"]),
               "em": x["capturado_em"].astimezone(tz).strftime("%d/%m/%Y %H:%M"), "d": x["dados"]}
              for x in d["extras"]]
    dados = {
        "alvo": inv["alvo_mascarado"], "inicio": inv["inicio_ms"], "fim": inv["fim_ms"], "fuso": inv["fuso"],
        "gran": inv["granularidade"], "status": inv["status"], "id": inv["id"],
        "justificativa": inv["justificativa"], "operador": inv["operador"],
        "eventos": evs, "cobertura": cob, "contas": contas, "extras": extras,
        "glossario": {k: list(v) for k, v in GLOSSARIO.items()}, "erros": ERROS,
        "base": bool(inv["parametros"].get("base_dias")),
        "base_ips": sorted({e["ip"] for e in (d.get("base_eventos") or [])}),
        "gerado": datetime.now(tz).strftime("%d/%m/%Y %H:%M"),
    }
    js = STATIC.read_text()
    return (TEMPLATE.replace("/*ECHARTS*/", js)
            .replace("/*DADOS*/", json.dumps(dados, ensure_ascii=False, default=str).replace("</", "<\\/")))


TEMPLATE = r"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Auditoria de acessos — investigação</title>
<style>
.viz-root{color-scheme:light;--surface-0:#f6f6f4;--surface-1:#fff;--border:#e2e2de;--text-primary:#191919;
--text-secondary:#666;--series-1:#257de0;--series-2:#f47230;--grid:#ececec;--good:#0b7a1f;--warn:#9a6700;--crit:#c62828;
--seq-1:#cce3fd;--seq-2:#84b9f3;--seq-3:#338ced;--seq-4:#1b64be;--seq-5:#0e3d7e;--focus:#1b64be}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])) .viz-root{color-scheme:dark;--surface-0:#111;
--surface-1:#191919;--border:#333;--text-primary:#efefef;--text-secondary:#9c9c9c;--series-1:#338ced;--series-2:#e76624;
--grid:#2a2a2a;--good:#4caf50;--warn:#e0a400;--crit:#ef5350}}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.viz-root{background:var(--surface-0);color:var(--text-primary);min-height:100vh;padding:20px 24px 48px}
h1{font-size:20px;margin:0}h2{font-size:15px;margin:0 0 10px}.mut{color:var(--text-secondary)}
header{display:flex;flex-wrap:wrap;gap:10px 18px;align-items:center;margin-bottom:14px}
.chip{display:inline-flex;gap:6px;align-items:center;border:1px solid var(--border);background:var(--surface-1);
border-radius:999px;padding:4px 12px;font-size:13px}
button.chip{cursor:pointer;color:inherit}button:focus-visible,select:focus-visible,input:focus-visible,tr:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.selo-parcial{border-color:var(--warn);font-weight:600}.selo-ok{border-color:var(--good);font-weight:600}
.filtros{display:flex;flex-wrap:wrap;gap:10px;align-items:center;background:var(--surface-1);border:1px solid var(--border);
border-radius:10px;padding:10px 12px;margin-bottom:14px}
select{background:var(--surface-1);color:inherit;border:1px solid var(--border);border-radius:6px;padding:5px 8px;font:inherit}
.ativos .chip{background:var(--seq-1);color:#0e3d7e;border-color:var(--seq-2)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
.kpi{background:var(--surface-1);border:1px solid var(--border);border-radius:10px;padding:12px 14px}
.kpi .v{font-size:26px;font-weight:650;font-variant-numeric:tabular-nums}.kpi .l{font-size:12px;color:var(--text-secondary)}
.kpi .v.dt{font-size:17px;padding-top:6px}.kpi .p{font-size:11.5px;color:var(--warn);margin-top:2px}
.card{background:var(--surface-1);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:14px}
.grid2{display:grid;grid-template-columns:3fr 2fr;gap:14px}@media(max-width:1000px){.grid2{grid-template-columns:1fr}}
.chart{height:300px}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;
border-bottom:1px solid var(--grid);vertical-align:top}th{color:var(--text-secondary);font-weight:600;position:sticky;top:0;background:var(--surface-1)}
td.n{text-align:right;font-variant-numeric:tabular-nums}tbody tr{cursor:pointer}tbody tr:hover{background:var(--grid)}
.scroll{max-height:360px;overflow:auto}.tag{font-size:11.5px;border-radius:4px;padding:1px 6px;border:1px solid var(--border);white-space:nowrap}
.coberto{color:var(--good)}.parcial{color:var(--warn)}.sem_dados{color:var(--crit)}
.tabs button{background:none;border:none;border-bottom:2px solid transparent;padding:6px 10px;color:inherit;font:inherit;cursor:pointer}
.tabs button[aria-selected=true]{border-color:var(--series-1);font-weight:600}
dialog{border:1px solid var(--border);border-radius:12px;background:var(--surface-1);color:var(--text-primary);max-width:640px;width:92vw}
dl{display:grid;grid-template-columns:170px 1fr;gap:4px 12px;margin:0}dt{color:var(--text-secondary)}
details pre{white-space:pre-wrap;font-size:12px;background:var(--surface-0);padding:8px;border-radius:6px}
.lista-dest li{margin:4px 0;cursor:pointer}.legenda{display:flex;gap:14px;font-size:12px;margin-bottom:4px}
.sw{display:inline-block;width:12px;height:12px;border-radius:3px;vertical-align:-2px;margin-right:4px}
.hach{background:repeating-linear-gradient(45deg,var(--grid),var(--grid) 3px,transparent 3px,transparent 6px);border:1px solid var(--border)}
.paginacao{display:flex;gap:8px;align-items:center;justify-content:flex-end;margin-top:6px}
.sr{position:absolute;left:-9999px}
</style></head>
<body><div class="viz-root" id="app">
<header>
  <h1>Auditoria de acessos</h1>
  <span class="chip" title="Identificador mascarado">Alvo <b id="alvo"></b></span>
  <span class="chip" id="periodo"></span>
  <button class="chip" id="seloCob" aria-haspopup="dialog"></button>
  <span class="chip mut" id="statusInv"></span>
</header>
<div class="filtros" role="group" aria-label="Filtros globais">
  <label>Instância <select id="fInst"></select></label>
  <label>Realm <select id="fRealm"></select></label>
  <label>Aplicação <select id="fApp"></select></label>
  <label><input type="checkbox" id="fTec"> mostrar eventos técnicos</label>
  <span class="ativos" id="ativos" aria-live="polite"></span>
  <button class="chip" id="limpar">Limpar filtros</button>
</div>
<section class="kpis" id="kpis" aria-label="Indicadores"></section>
<div class="grid2">
  <section class="card"><h2>Logins e falhas por <span id="granTxt"></span></h2>
    <div class="legenda"><span><i class="sw" style="background:var(--series-1)"></i>Logins</span>
      <span><i class="sw" style="background:var(--series-2)"></i>Falhas de login</span>
      <span><i class="sw hach"></i>Sem dados em parte dos realms</span></div>
    <div id="cBarras" class="chart" role="img" aria-label="Gráfico de barras de logins e falhas por janela; tabela equivalente abaixo"></div>
    <details><summary>Ver como tabela</summary><div class="scroll" id="tBarras"></div></details></section>
  <section class="card"><h2>Logins por dia da semana e hora</h2>
    <div id="cHeat" class="chart" role="img" aria-label="Mapa de calor de logins por dia da semana e hora, com o número em cada célula"></div></section>
</div>
<div class="grid2">
  <section class="card"><h2>Por instância, realm e aplicação</h2><div class="scroll" id="tApp"></div></section>
  <section class="card"><h2>Destaques</h2><ul class="lista-dest" id="dest"></ul></section>
</div>
<section class="card"><h2>Por IP</h2><div class="scroll" id="tIp"></div></section>
<section class="card"><h2>Linha do tempo de eventos <span class="mut" id="ntl"></span></h2><div class="scroll" id="tTl" style="max-height:460px"></div>
  <div class="paginacao"><button class="chip" id="pAnt">Anterior</button><span id="pInfo" class="mut"></span><button class="chip" id="pProx">Próxima</button></div></section>
<section class="card"><div class="tabs" role="tablist"><button role="tab" aria-selected="true" data-tab="contas">Contas encontradas</button>
  <button role="tab" aria-selected="false" data-tab="sessoes">Sessões ativas</button><button role="tab" aria-selected="false" data-tab="admin">Alterações na conta</button>
  <button role="tab" aria-selected="false" data-tab="cobertura">Cobertura</button></div><div id="tabBody" class="scroll"></div></section>
<p class="mut" id="rodape"></p>
<dialog id="dlg"><form method="dialog"><div id="dlgBody"></div><p style="text-align:right"><button class="chip">Fechar</button></p></form></dialog>
</div>
<script>/*ECHARTS*/</script>
<script>
const D=/*DADOS*/;
const G=D.glossario, $=s=>document.querySelector(s);
const nomeEv=t=>(G[t]||[t])[0], cat=t=>(G[t]||[t,'Outro'])[1];
const fmt=new Intl.DateTimeFormat('pt-BR',{timeZone:D.fuso,dateStyle:'short',timeStyle:'medium'});
const fmtD=new Intl.DateTimeFormat('pt-BR',{timeZone:D.fuso,dateStyle:'short'});
const utc=new Intl.DateTimeFormat('pt-BR',{timeZone:'UTC',dateStyle:'short',timeStyle:'medium'});
const LOGIN=new Set(['LOGIN','IDENTITY_PROVIDER_LOGIN']),FALHA=new Set(['LOGIN_ERROR','IDENTITY_PROVIDER_LOGIN_ERROR']);
const css=n=>getComputedStyle($('#app')).getPropertyValue(n).trim();
let F={i:'',r:'',c:'',tec:false,sel:null},pag=0;const PP=100;
function lerHash(){const p=new URLSearchParams(location.hash.slice(1));F.i=p.get('i')||'';F.r=p.get('r')||'';F.c=p.get('c')||'';F.tec=p.get('tec')==='1'}
function gravarHash(){const p=new URLSearchParams();if(F.i)p.set('i',F.i);if(F.r)p.set('r',F.r);if(F.c)p.set('c',F.c);if(F.tec)p.set('tec','1');history.replaceState(null,'','#'+p)}
function esc(s){return s==null?'':String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function base(){return D.eventos.filter(e=>(!F.i||e.i===F.i)&&(!F.r||e.r===F.r)&&(!F.c||e.c===F.c)&&(F.tec||cat(e.y)!=='Técnico'))}
function cobFiltrada(){return D.cobertura.filter(c=>(!F.i||c.i===F.i)&&(!F.r||c.r===F.r))}
function fracoes(){const cb=cobFiltrada();const ok=cb.filter(c=>c.cl==='coberto').length;
  const dias=Math.max(1,Math.round((D.fim-D.inicio)/864e5));const comConta=cb.filter(c=>c.conta&&c.cl!=='sem_dados');
  let desde=D.inicio;comConta.forEach(c=>{if(c.desde&&c.desde>desde)desde=c.desde});
  let perd=new Set();comConta.forEach(c=>(c.de||'').split('; ').forEach(p=>{if(p.includes(':')&&(p.includes('divergente')||p.includes('expirado')))p.split(':')[1].split(',').forEach(x=>perd.add(x.trim()))}));
  let diasOk=comConta.length?Math.max(0,Math.round((D.fim-desde)/864e5)-perd.size):(ok===cb.length?dias:0);
  return {ok,tot:cb.length,dias:Math.min(diasOk,dias),diasTot:dias,completa:ok===cb.length&&diasOk>=dias}}
function janela(t){const d=new Date(t);const p=Object.fromEntries(new Intl.DateTimeFormat('en-CA',{timeZone:D.fuso,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',hourCycle:'h23',weekday:'short'}).formatToParts(d).map(x=>[x.type,x.value]));
  if(D.gran==='hora')return `${p.year}-${p.month}-${p.day} ${p.hour}h`;if(D.gran==='mes')return `${p.year}-${p.month}`;
  if(D.gran==='semana'){const dw={Mon:0,Tue:1,Wed:2,Thu:3,Fri:4,Sat:5,Sun:6}[p.weekday];const m=new Date(Date.UTC(+p.year,+p.month-1,+p.day-dw));return 'sem. '+m.toISOString().slice(0,10)}
  return `${p.year}-${p.month}-${p.day}`}
function todasJanelas(){const out=[];const passo={hora:36e5,dia:864e5,semana:864e5,mes:864e5}[D.gran];const s=new Set();
  for(let t=D.inicio;t<D.fim;t+=passo){const j=janela(t);if(!s.has(j)){s.add(j);out.push([j,t])}}return out}
function render(){gravarHash();const ev=base();const fr=fracoes();
  // cabeçalho
  $('#alvo').textContent=D.alvo;$('#periodo').textContent=`${fmtD.format(D.inicio)} – ${fmtD.format(D.fim-1)} · ${D.fuso}`;
  const sc=$('#seloCob');sc.className='chip '+(fr.completa?'selo-ok':'selo-parcial');
  sc.innerHTML=`Cobertura: realms ${fr.ok}/${fr.tot} · tempo ${fr.dias}/${fr.diasTot} dias ▸`;
  $('#statusInv').textContent={concluida:'Concluída',concluida_com_lacunas:'Concluída com lacunas',parcial:'Parcial — PRELIMINAR',coletando:'Coletando — PRELIMINAR'}[D.status]||D.status;
  $('#granTxt').textContent={hora:'hora',dia:'dia',semana:'semana',mes:'mês'}[D.gran];
  // KPIs
  const lg=ev.filter(e=>LOGIN.has(e.y)),fl=ev.filter(e=>FALHA.has(e.y));
  const parc=fr.completa?'':`parcial · realms ${fr.ok}/${fr.tot} · ${fr.dias}/${fr.diasTot} dias`;
  const val=n=>(n===0&&!fr.completa)?`0 <span class="mut" style="font-size:12px">(parcial)</span>`:n.toLocaleString('pt-BR');
  const ks=[['Logins',val(lg.length)],['Falhas de login',val(fl.length)],['Aplicações',val(new Set(lg.map(e=>e.c)).size)],
    ['IPs',val(new Set([...lg,...fl].map(e=>e.ip)).size)],['Primeiro acesso',lg.length?fmt.format(Math.min(...lg.map(e=>e.t))):'—'],
    ['Último acesso',lg.length?fmt.format(Math.max(...lg.map(e=>e.t))):'—']];
  $('#kpis').innerHTML=ks.map(([l,v])=>`<div class="kpi" title="${esc(parc)}"><div class="l">${l}</div><div class="v ${/acesso/.test(l)?'dt':''}">${v}</div>${parc?`<div class="p">${parc}</div>`:''}</div>`).join('');
  // filtros ativos
  $('#ativos').innerHTML=[F.i&&`Instância: ${F.i}`,F.r&&`Realm: ${F.r}`,F.c&&`Aplicação: ${F.c}`,F.sel&&F.sel.rot].filter(Boolean).map(x=>`<span class="chip">${esc(x)}</span>`).join(' ');
  barras(ev);heat(lg);tabelas(ev);destaques(ev);tl(ev);aba(abaAtual)}
function semDadosPorJanela(){const cb=cobFiltrada().filter(c=>c.conta);const tot=cb.length;
  return t=>({falta:cb.filter(c=>c.cl==='sem_dados'||(c.desde&&t<c.desde)).length,tot})}
let chB,chH;
function barras(ev){const js=todasJanelas();const idx=new Map(js.map(([j],k)=>[j,k]));const L=js.map(()=>0),E=js.map(()=>0);
  ev.forEach(e=>{const k=idx.get(janela(e.t));if(k==null)return;if(LOGIN.has(e.y))L[k]++;else if(FALHA.has(e.y))E[k]++});
  const sd=semDadosPorJanela();const falta=js.map(([,t])=>sd(t));const mx=Math.max(1,...L.map((v,k)=>v+E[k]));
  const hach=js.map((_,k)=>falta[k].falta?mx:0);
  chB=chB||echarts.init($('#cBarras'));
  chB.setOption({animation:false,grid:{left:46,right:12,top:10,bottom:40},textStyle:{color:css('--text-secondary')},
    tooltip:{trigger:'axis',formatter:ps=>{const k=ps[0].dataIndex;const f=falta[k];return `<b>${js[k][0]}</b><br>Logins: ${L[k]}<br>Falhas de login: ${E[k]}`+(f.falta?`<br><i>sem dados em ${f.falta} de ${f.tot} realm·conta</i>`:'')}},
    xAxis:{type:'category',data:js.map(x=>x[0]),axisLabel:{color:css('--text-secondary')},axisLine:{lineStyle:{color:css('--grid')}}},
    yAxis:{type:'value',splitLine:{lineStyle:{color:css('--grid')}},axisLabel:{color:css('--text-secondary')}},
    series:[{name:'sem dados',type:'bar',data:hach,barGap:'-100%',silent:true,itemStyle:{color:{image:padrao(),repeat:'repeat'},opacity:.7},z:0},
      {name:'Logins',type:'bar',stack:'a',data:L,itemStyle:{color:css('--series-1'),borderColor:css('--surface-1'),borderWidth:1}},
      {name:'Falhas de login',type:'bar',stack:'a',data:E,itemStyle:{color:css('--series-2'),borderRadius:[3,3,0,0],borderColor:css('--surface-1'),borderWidth:1}}]},true);
  chB.off('click');chB.on('click',p=>{const t0=js[p.dataIndex][1];const j=js[p.dataIndex][0];F.sel={rot:`Janela ${j}`,f:e=>janela(e.t)===j};pag=0;render()});
  $('#tBarras').innerHTML=tab(['Janela','Logins','Falhas','Sem dados (realm·conta)'],js.map(([j],k)=>[j,L[k],E[k],falta[k].falta?`${falta[k].falta}/${falta[k].tot}`:'']),[1,2])}
function padrao(){const c=document.createElement('canvas');c.width=c.height=8;const x=c.getContext('2d');x.strokeStyle=css('--text-secondary');x.lineWidth=1;x.beginPath();x.moveTo(0,8);x.lineTo(8,0);x.stroke();return c}
function heat(lg){const dias=['seg','ter','qua','qui','sex','sáb','dom'];const m={};
  lg.forEach(e=>{const p=Object.fromEntries(new Intl.DateTimeFormat('en-US',{timeZone:D.fuso,weekday:'short',hour:'2-digit',hourCycle:'h23'}).formatToParts(new Date(e.t)).map(x=>[x.type,x.value]));
    const dw={Mon:0,Tue:1,Wed:2,Thu:3,Fri:4,Sat:5,Sun:6}[p.weekday];const k=dw+'-'+(+p.hour);m[k]=(m[k]||0)+1});
  const data=[];let mx=1;for(let d=0;d<7;d++)for(let h=0;h<24;h++){const v=m[d+'-'+h]||0;mx=Math.max(mx,v);data.push([h,d,v])}
  chH=chH||echarts.init($('#cHeat'));
  chH.setOption({animation:false,grid:{left:40,right:10,top:6,bottom:56},tooltip:{formatter:p=>`${dias[p.value[1]]} ${p.value[0]}h: ${p.value[2]} logins`},
    xAxis:{type:'category',data:[...Array(24).keys()].map(h=>h+'h'),axisLabel:{color:css('--text-secondary'),interval:2},splitArea:{show:false}},
    yAxis:{type:'category',data:dias,inverse:true,axisLabel:{color:css('--text-secondary')}},
    visualMap:{min:0,max:mx,orient:'horizontal',left:'center',bottom:0,itemHeight:120,textStyle:{color:css('--text-secondary')},inRange:{color:[css('--seq-1'),css('--seq-3'),css('--seq-5')]}},
    series:[{type:'heatmap',data,label:{show:true,fontSize:9,color:'#111',formatter:p=>p.value[2]||''},itemStyle:{borderColor:css('--surface-1'),borderWidth:2}}]},true);
  chH.off('click');chH.on('click',p=>{const [h,d]=p.value;F.sel={rot:`${dias[d]} ${h}h`,f:e=>{const q=Object.fromEntries(new Intl.DateTimeFormat('en-US',{timeZone:D.fuso,weekday:'short',hour:'2-digit',hourCycle:'h23'}).formatToParts(new Date(e.t)).map(x=>[x.type,x.value]));return {Mon:0,Tue:1,Wed:2,Thu:3,Fri:4,Sat:5,Sun:6}[q.weekday]===d&&+q.hour===h}};pag=0;render()})}
function tab(cab,linhas,num=[],cliques=null){return `<table><thead><tr>${cab.map(c=>`<th scope="col">${c}</th>`).join('')}</tr></thead><tbody>${linhas.map((l,k)=>`<tr tabindex="0" ${cliques?`data-k="${k}"`:''}>${l.map((v,j)=>`<td class="${num.includes(j)?'n':''}">${v==null?'':v}</td>`).join('')}</tr>`).join('')}</tbody></table>`}
function agrupa(ev,chave){const m=new Map();ev.forEach(e=>{const k=chave(e);const o=m.get(k)||{n:0,l:0,f:0,a:Infinity,z:0,ips:new Set(),onde:new Set()};o.n++;if(LOGIN.has(e.y))o.l++;if(FALHA.has(e.y))o.f++;o.a=Math.min(o.a,e.t);o.z=Math.max(o.z,e.t);o.ips.add(e.ip);o.onde.add(e.i+'/'+e.r);m.set(k,o)});return [...m.entries()].sort((a,b)=>b[1].n-a[1].n)}
function tabelas(ev){const ap=agrupa(ev,e=>e.i+'|'+e.r+'|'+e.c);
  $('#tApp').innerHTML=tab(['Instância','Realm','Aplicação','Logins','Falhas','Primeiro','Último'],ap.map(([k,o])=>{const [i,r,c]=k.split('|');return [esc(i),esc(r),esc(c),o.l,o.f,fmt.format(o.a),fmt.format(o.z)]}),[3,4],1);
  $('#tApp').querySelectorAll('tbody tr').forEach(tr=>{const go=()=>{const [i,r,c]=ap[+tr.dataset.k][0].split('|');F.i=i;F.r=r;F.c=c;F.sel=null;pag=0;sync();render()};tr.onclick=go;tr.onkeydown=e=>{if(e.key==='Enter')go()}});
  const ip=agrupa(ev,e=>e.ip);
  $('#tIp').innerHTML=tab(['IP','Eventos','Logins','Falhas','Primeiro','Último','Onde'],ip.map(([k,o])=>[esc(k),o.n,o.l,o.f,fmt.format(o.a),fmt.format(o.z),esc([...o.onde].join(', '))]),[1,2,3],1);
  $('#tIp').querySelectorAll('tbody tr').forEach(tr=>{const go=()=>{const v=ip[+tr.dataset.k][0];F.sel={rot:`IP ${v}`,f:e=>e.ip===v};pag=0;render()};tr.onclick=go;tr.onkeydown=e=>{if(e.key==='Enter')go()}})}
function destaques(ev){const fe=e=>{const p=Object.fromEntries(new Intl.DateTimeFormat('en-US',{timeZone:D.fuso,weekday:'short',hour:'2-digit',hourCycle:'h23'}).formatToParts(new Date(e.t)).map(x=>[x.type,x.value]));return ['Sat','Sun'].includes(p.weekday)||+p.hour<7||+p.hour>=19};
  const fora=ev.filter(e=>LOGIN.has(e.y)&&fe(e));
  const fl=ev.filter(e=>FALHA.has(e.y)).sort((a,b)=>a.t-b.t);const raj=[];const por={};fl.forEach(e=>(por[e.i+'|'+e.r+'|'+e.u]=por[e.i+'|'+e.r+'|'+e.u]||[]).push(e));
  Object.entries(por).forEach(([k,a])=>{let i=0,at=null;for(let j=0;j<a.length;j++){while(a[j].t-a[i].t>6e5)i++;if(j-i+1>=5){if(at&&a[i].t<=at.fim){at.fim=a[j].t;at.ids.add(a[j].id)}else{at={k,ini:a[i].t,fim:a[j].t,ids:new Set(a.slice(i,j+1).map(x=>x.id))};raj.push(at)}}}});
  const itens=[];
  itens.push([`Fora do expediente (seg–sex 07–19h): ${fora.length} login(s)`,{rot:'Fora do expediente',f:e=>LOGIN.has(e.y)&&fe(e)}]);
  raj.forEach(r=>{const [i,re,u]=r.k.split('|');itens.push([`Rajada: ${r.ids.size} falhas de login em ${i}/${re} (${u}) entre ${fmt.format(r.ini)} e ${fmt.format(r.fim)}`,{rot:'Rajada',f:e=>r.ids.has(e.id)}])});
  if(!D.base)itens.push(['IP novo: sem base de comparação (coleta sem os 30 dias anteriores)',null]);
  else{const b=new Set(D.base_ips);const novos=[...new Set(ev.map(e=>e.ip))].filter(x=>!b.has(x));itens.push([`IP novo: ${novos.length} IP(s) ausentes nos 30 dias anteriores`,{rot:'IP novo',f:e=>novos.includes(e.ip)}])}
  $('#dest').innerHTML=itens.map(([t,f],k)=>`<li tabindex="0" data-k="${k}">${esc(t)}</li>`).join('');
  $('#dest').querySelectorAll('li').forEach(li=>{const it=itens[+li.dataset.k];if(!it[1])return;const go=()=>{F.sel=it[1];pag=0;render()};li.onclick=go;li.onkeydown=e=>{if(e.key==='Enter')go()}})}
let tlAtual=[];
function tl(ev){tlAtual=(F.sel?ev.filter(F.sel.f):ev).slice().sort((a,b)=>b.t-a.t);const n=tlAtual.length;const pg=Math.max(1,Math.ceil(n/PP));pag=Math.min(pag,pg-1);
  $('#ntl').textContent=`(${n.toLocaleString('pt-BR')} eventos${F.sel?' · filtro: '+F.sel.rot:''})`;
  const fat=tlAtual.slice(pag*PP,pag*PP+PP);
  $('#tTl').innerHTML=tab(['Data e hora','Instância','Realm','Conta','Evento','Aplicação','IP','Erro'],fat.map(e=>[fmt.format(e.t),esc(e.i),esc(e.r),esc(e.u),esc(nomeEv(e.y)),esc(e.c),esc(e.ip),esc(D.erros[e.er]||e.er||'')]),[],1);
  $('#tTl').querySelectorAll('tbody tr').forEach(tr=>{const go=()=>detalhe(fat[+tr.dataset.k]);tr.onclick=go;tr.onkeydown=e=>{if(e.key==='Enter')go()}});
  $('#pInfo').textContent=`página ${pag+1} de ${pg}`;$('#pAnt').disabled=pag===0;$('#pProx').disabled=pag>=pg-1}
function detalhe(e){const d=e.d||{};$('#dlgBody').innerHTML=`<h2>${esc(nomeEv(e.y))}</h2><dl>
 <dt>Data e hora (${esc(D.fuso)})</dt><dd>${fmt.format(e.t)}</dd><dt>UTC</dt><dd>${utc.format(e.t)}</dd>
 <dt>Instância / realm</dt><dd>${esc(e.i)} / ${esc(e.r)}</dd><dt>Conta</dt><dd>${esc(e.u)}</dd>
 <dt>Aplicação</dt><dd>${esc(e.c)}</dd><dt>IP</dt><dd>${esc(e.ip)}</dd><dt>Sessão</dt><dd>${esc(e.s||'—')}</dd>
 <dt>Erro</dt><dd>${esc(D.erros[e.er]||e.er||'—')}</dd><dt>Método</dt><dd>${esc(d.auth_method||'—')}</dd>
 <dt>Endereço de retorno</dt><dd>${esc(d.redirect_uri||'—')}</dd><dt>Código do evento</dt><dd>${esc(e.y)}</dd></dl>
 <details><summary>Avançado: dados brutos</summary><pre>${esc(JSON.stringify({id:e.id,time:e.t,type:e.y,clientId:e.c,ipAddress:e.ip,sessionId:e.s,error:e.er,details:d},null,2))}</pre></details>`;$('#dlg').showModal()}
let abaAtual='contas';
function aba(n){abaAtual=n;document.querySelectorAll('[role=tab]').forEach(b=>b.setAttribute('aria-selected',b.dataset.tab===n));
  const cls={coberto:'Coberto',parcial:'Parcial',sem_dados:'Sem dados'};let h='';
  if(n==='contas')h=tab(['Instância','Realm','Conta','ID','Via','Origem','Habilitada','Criada'],D.contas.filter(c=>(!F.i||c.i===F.i)&&(!F.r||c.r===F.r)).map(c=>[esc(c.i),esc(c.r),esc(c.u),`<span class="mut">${esc(c.id||'—')}</span>`,esc(c.via),esc(c.origem),c.hab==null?'—':c.hab?'sim':'não',esc(c.criado||'')]));
  if(n==='sessoes'){const s=D.extras.filter(x=>x.tipo==='sessao');h=s.length?tab(['Fotografia','Instância','Realm','Conta','IP','Início','Último acesso'],s.map(x=>[x.em,esc(x.i),esc(x.r),esc(x.u),esc(x.d.ipAddress),fmt.format(x.d.start),fmt.format(x.d.lastAccess)])):`<p class="mut">Nenhuma sessão ativa na fotografia de ${esc(D.gerado)}.</p>`}
  if(n==='admin'){const s=D.extras.filter(x=>x.tipo==='admin');h=s.length?tab(['Data e hora','Instância','Realm','Conta','Operação','Recurso'],s.map(x=>[fmt.format(x.d.time),esc(x.i),esc(x.r),esc(x.u),esc(x.d.operationType),esc(x.d.resourcePath)])):'<p class="mut">Nenhuma alteração administrativa registrada no período.</p>'}
  if(n==='cobertura')h=tab(['Instância','Realm','Conta','Classe','Situação','Próximo passo'],cobFiltrada().map(c=>[esc(c.i),esc(c.r),esc(c.u||'—'),`<span class="tag ${c.cl}">${cls[c.cl]}</span>`,esc(c.de||''),esc(c.ac||'')]));
  $('#tabBody').innerHTML=h}
function opcoes(sel,vals,atual,rot){sel.innerHTML=`<option value="">${rot}</option>`+vals.map(v=>`<option ${v===atual?'selected':''}>${esc(v)}</option>`).join('')}
function sync(){opcoes($('#fInst'),[...new Set(D.eventos.map(e=>e.i).concat(D.cobertura.map(c=>c.i)))].sort(),F.i,'Todas');
  opcoes($('#fRealm'),[...new Set(D.cobertura.filter(c=>!F.i||c.i===F.i).map(c=>c.r))].sort(),F.r,'Todos');
  opcoes($('#fApp'),[...new Set(D.eventos.filter(e=>(!F.i||e.i===F.i)&&(!F.r||e.r===F.r)).map(e=>e.c))].sort(),F.c,'Todas');$('#fTec').checked=F.tec}
$('#fInst').onchange=e=>{F.i=e.target.value;F.r='';F.c='';pag=0;sync();render()};
$('#fRealm').onchange=e=>{F.r=e.target.value;F.c='';pag=0;sync();render()};
$('#fApp').onchange=e=>{F.c=e.target.value;pag=0;render()};$('#fTec').onchange=e=>{F.tec=e.target.checked;render()};
$('#limpar').onclick=()=>{F={i:'',r:'',c:'',tec:false,sel:null};pag=0;sync();render()};
$('#pAnt').onclick=()=>{pag--;tl(base())};$('#pProx').onclick=()=>{pag++;tl(base())};
$('#seloCob').onclick=()=>{aba('cobertura');document.querySelector('.tabs').scrollIntoView({behavior:'smooth'})};
document.querySelectorAll('[role=tab]').forEach(b=>b.onclick=()=>aba(b.dataset.tab));
$('#rodape').textContent=`Investigação ${D.id} · operador ${D.operador} · justificativa: ${D.justificativa} · gerado em ${D.gerado}. Horários no fuso ${D.fuso}; o horário de cada evento vem do relógio do servidor Keycloak.`;
window.addEventListener('resize',()=>{chB&&chB.resize();chH&&chH.resize()});
lerHash();sync();render();
</script></body></html>
"""
