(function () {
  'use strict';

  // ===================================================
  // Datos de contacto (ofuscados)
  // ===================================================
  var u = ['carlos', 'undersoftware', 'cl'];
  var EMAIL = u[0] + '@' + u[1] + '.' + u[2];
  var PHONE = '+56974873037';
  var SITE  = 'https://www.undersoftware.cl/';
  var FULLNAME = 'Carlos Matías Oliver Carvajal';

  document.getElementById('act-call').setAttribute('href', 'tel:' + PHONE);
  document.getElementById('act-mail').setAttribute('href', 'mailto:' + EMAIL);
  var ctaContact = document.getElementById('cta-contact');
  if (ctaContact) {
    ctaContact.setAttribute('href', 'mailto:' + EMAIL +
      '?subject=' + encodeURIComponent('Consulta · Caso técnico') +
      '&body=' + encodeURIComponent('Hola Carlos,\n\nQuiero conversar sobre un caso de:\n\n[describe brevemente]\n\nGracias.'));
  }

  // ===================================================
  // vCard download
  // ===================================================
  document.getElementById('btn-vcard').addEventListener('click', function () {
    var vcf = [
      'BEGIN:VCARD',
      'VERSION:3.0',
      'N:Oliver Carvajal;Carlos;Matías;;',
      'FN:' + FULLNAME,
      'ORG:Undersoftware',
      'TITLE:Ingeniero de Software / Líder de Proyectos TI',
      'TEL;TYPE=CELL,VOICE:' + PHONE,
      'EMAIL;TYPE=INTERNET,PREF:' + EMAIL,
      'URL:' + SITE,
      'ADR;TYPE=WORK:;;Santiago;Región Metropolitana;;;Chile',
      'NOTE:Banca · Pagos · Observabilidad transaccional',
      'END:VCARD'
    ].join('\r\n');
    var blob = new Blob([vcf], { type: 'text/vcard;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'Carlos_Oliver.vcf';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  });

  // ===================================================
  // Compartir + Copiar
  // ===================================================
  var shareData = {
    title: 'Carlos Oliver · Undersoftware',
    text: 'Ingeniería para sistemas críticos · Banca · Pagos · Observabilidad',
    url: SITE
  };
  document.getElementById('btn-share').addEventListener('click', async function () {
    if (navigator.share) {
      try { await navigator.share(shareData); } catch (_) {}
    } else { copyLink(); }
  });
  function copyLink () {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(SITE).then(function () {
        flashBtn(document.getElementById('btn-copy'), '✓');
      });
    }
  }
  document.getElementById('btn-copy').addEventListener('click', copyLink);
  function flashBtn (el, txt) {
    var orig = el.innerHTML;
    el.innerHTML = '<span style="font-size:14px;font-weight:700;color:var(--mint)">' + txt + '</span>';
    setTimeout(function () { el.innerHTML = orig; }, 1400);
  }

  // ===================================================
  // QR
  // ===================================================
  document.getElementById('qr-img').src =
    'https://api.qrserver.com/v1/create-qr-code/?data=' + encodeURIComponent(SITE) +
    '&size=200x200&margin=8&color=050B1F&bgcolor=FFFFFF&format=svg';

  // ===================================================
  // Helpers de formato
  // ===================================================
  function fmtCLP (n) {
    return n.toLocaleString('es-CL', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }
  function fmtCLPint (n) {
    return Math.round(n).toLocaleString('es-CL');
  }
  function fmtTime (d) {
    return d.toLocaleTimeString('es-CL', { hour: '2-digit', minute: '2-digit' });
  }
  function timeAgo (date) {
    var s = Math.floor((Date.now() - date.getTime()) / 1000);
    if (s < 60) return 'hace ' + s + 's';
    if (s < 3600) return 'hace ' + Math.floor(s/60) + 'm';
    if (s < 86400) return 'hace ' + Math.floor(s/3600) + 'h';
    return 'hace ' + Math.floor(s/86400) + 'd';
  }
  function escHTML (s) {
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }
  function safeUrl (url) {
    try {
      var u = new URL(url);
      return (u.protocol === 'https:' || u.protocol === 'http:') ? u.href : '#';
    } catch (_) { return '#'; }
  }

  // ===================================================
  // INTEGRACIÓN 1 · USD/CLP (Banco Central via mindicador.cl)
  // ===================================================
  var FX_EL = {
    chart: document.getElementById('fx-chart'),
    current: document.getElementById('fx-current'),
    change: document.getElementById('fx-change'),
    updated: document.getElementById('fx-updated'),
    points: document.getElementById('fx-points'),
    min: document.getElementById('fx-min'),
    max: document.getElementById('fx-max'),
    avg: document.getElementById('fx-avg')
  };
  var FX_DATA = [];

  async function fetchDolar () {
    try {
      var r = await fetch('https://mindicador.cl/api/dolar', { cache: 'no-store' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      var j = await r.json();
      if (!j.serie || !j.serie.length) throw new Error('serie vacía');
      var serie = j.serie.slice().reverse().map(function (p) {
        return { fecha: new Date(p.fecha), valor: Number(p.valor) };
      });
      renderFx(serie, 'Banco Central · mindicador.cl');
    } catch (err) {
      try {
        var r2 = await fetch('https://open.er-api.com/v6/latest/USD');
        var j2 = await r2.json();
        var v = j2 && j2.rates && j2.rates.CLP;
        if (!v) throw new Error('sin rate');
        renderFx([{ fecha: new Date(), valor: Number(v) }], 'Fallback · open.er-api.com');
      } catch (e2) {
        FX_EL.chart.innerHTML = '<div class="skeleton" style="color:var(--danger)">Sin conexión a la fuente</div>';
        FX_EL.updated.textContent = 'Reintentando…';
      }
    }
  }

  function renderFx (serie, source) {
    FX_DATA = serie;
    var last = serie[serie.length - 1];
    var prev = serie.length > 1 ? serie[serie.length - 2] : last;
    var diff = last.valor - prev.valor;
    var pct = prev.valor ? (diff / prev.valor) * 100 : 0;

    FX_EL.current.textContent = fmtCLP(last.valor);
    var arrow = diff >= 0 ? '▲' : '▼';
    FX_EL.change.className = 'fx-change ' + (diff >= 0 ? 'up' : 'down');
    FX_EL.change.innerHTML = '<span class="arrow">' + arrow + '</span> '
      + (diff >= 0 ? '+' : '') + fmtCLP(diff) + ' (' + (diff >= 0 ? '+' : '') + pct.toFixed(2) + '%)';

    var values = serie.map(function (p) { return p.valor; });
    var minV = Math.min.apply(null, values);
    var maxV = Math.max.apply(null, values);
    var avgV = values.reduce(function (a, b) { return a + b; }, 0) / values.length;

    FX_EL.min.textContent = '$' + fmtCLP(minV);
    FX_EL.max.textContent = '$' + fmtCLP(maxV);
    FX_EL.avg.textContent = '$' + fmtCLP(avgV);
    FX_EL.points.textContent = serie.length + ' puntos';
    FX_EL.updated.textContent = 'Actualizado ' + fmtTime(new Date()) + ' · ' + source;

    drawFxChart(serie, minV, maxV);
  }

  function drawFxChart (serie, minV, maxV) {
    var el = FX_EL.chart;
    var W = el.clientWidth || 480;
    var H = el.clientHeight || 160;
    var pad = { t: 8, r: 8, b: 24, l: 8 };
    var iw = W - pad.l - pad.r;
    var ih = H - pad.t - pad.b;
    var range = maxV - minV || 1;
    var yMin = minV - range * 0.08;
    var yMax = maxV + range * 0.08;
    function x (i) { return pad.l + (serie.length === 1 ? iw / 2 : (i / (serie.length - 1)) * iw); }
    function y (v) { return pad.t + ih - ((v - yMin) / (yMax - yMin)) * ih; }

    var line = '';
    for (var i = 0; i < serie.length; i++) {
      line += (i === 0 ? 'M' : 'L') + x(i).toFixed(1) + ' ' + y(serie[i].valor).toFixed(1) + ' ';
    }
    var area = line + 'L' + x(serie.length-1).toFixed(1) + ' ' + (pad.t+ih) + ' L' + x(0).toFixed(1) + ' ' + (pad.t+ih) + ' Z';
    var grid = '';
    for (var g = 0; g < 3; g++) {
      var gy = (pad.t + (ih / 2) * g).toFixed(1);
      grid += '<line x1="'+pad.l+'" x2="'+(W-pad.r)+'" y1="'+gy+'" y2="'+gy+'" stroke="rgba(255,255,255,0.04)" stroke-width="1"/>';
    }
    var lbls = '';
    function dLbl(d){ return d.toLocaleDateString('es-CL', { day: '2-digit', month: 'short' }); }
    if (serie.length > 1) {
      lbls += '<text x="'+x(0)+'" y="'+(H-4)+'" fill="rgba(255,255,255,0.4)" font-size="9.5" font-family="JetBrains Mono, monospace">'+dLbl(serie[0].fecha)+'</text>';
      var mi = Math.floor(serie.length/2);
      lbls += '<text x="'+x(mi)+'" y="'+(H-4)+'" fill="rgba(255,255,255,0.4)" font-size="9.5" font-family="JetBrains Mono, monospace" text-anchor="middle">'+dLbl(serie[mi].fecha)+'</text>';
      lbls += '<text x="'+x(serie.length-1)+'" y="'+(H-4)+'" fill="rgba(255,255,255,0.4)" font-size="9.5" font-family="JetBrains Mono, monospace" text-anchor="end">hoy</text>';
    }
    var lx = x(serie.length-1).toFixed(1);
    var ly = y(serie[serie.length-1].valor).toFixed(1);

    el.innerHTML = '<svg viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none">' +
      '<defs>' +
      '<linearGradient id="fxGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#4ADE80" stop-opacity="0.35"/><stop offset="100%" stop-color="#4ADE80" stop-opacity="0"/></linearGradient>' +
      '<linearGradient id="fxLine" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="#06B6D4"/><stop offset="100%" stop-color="#4ADE80"/></linearGradient>' +
      '</defs>' + grid +
      '<path d="'+area+'" fill="url(#fxGrad)" />' +
      '<path d="'+line+'" fill="none" stroke="url(#fxLine)" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round"/>' +
      '<circle cx="'+lx+'" cy="'+ly+'" r="4" fill="#4ADE80"/>' +
      '<circle cx="'+lx+'" cy="'+ly+'" r="8" fill="#4ADE80" opacity="0.25"><animate attributeName="r" values="4;14;4" dur="2s" repeatCount="indefinite"/><animate attributeName="opacity" values="0.4;0;0.4" dur="2s" repeatCount="indefinite"/></circle>' +
      lbls + '</svg>';
  }

  // ===================================================
  // INTEGRACIÓN 2 · CRIPTO en CLP (CoinGecko)
  // ===================================================
  var COINS = [
    { id: 'bitcoin',  symbol: 'BTC', name: 'Bitcoin',   cls: 'btc'  },
    { id: 'ethereum', symbol: 'ETH', name: 'Ethereum',  cls: 'eth'  },
    { id: 'tether',   symbol: 'USDT',name: 'Tether',    cls: 'usdt' }
  ];

  async function fetchCrypto () {
    var listEl = document.getElementById('crypto-list');
    var updEl = document.getElementById('crypto-updated');
    try {
      var ids = COINS.map(function (c) { return c.id; }).join(',');
      var url = 'https://api.coingecko.com/api/v3/simple/price'
              + '?ids=' + ids
              + '&vs_currencies=clp'
              + '&include_24hr_change=true';
      var r = await fetch(url);
      if (!r.ok) throw new Error('HTTP ' + r.status);
      var j = await r.json();

      var rows = COINS.map(function (c) {
        var d = j[c.id];
        if (!d) return '';
        var price = d.clp;
        var chg = d.clp_24h_change || 0;
        var chgClass = chg >= 0 ? 'up' : 'down';
        var chgArr = chg >= 0 ? '▲' : '▼';
        return '' +
          '<div class="crypto-row">' +
            '<div class="crypto-icon ' + c.cls + '">' + escHTML(c.symbol.slice(0,3)) + '</div>' +
            '<div class="crypto-name">' +
              '<div class="n">' + escHTML(c.name) + '</div>' +
              '<div class="s">' + escHTML(c.symbol) + ' / CLP</div>' +
            '</div>' +
            '<div class="crypto-price">$' + fmtCLPint(price) + '<span class="clp"> CLP</span></div>' +
            '<div class="crypto-change ' + chgClass + '">' + chgArr + ' ' + Math.abs(chg).toFixed(2) + '%</div>' +
          '</div>';
      }).join('');

      listEl.innerHTML = rows;
      updEl.textContent = 'Actualizado ' + fmtTime(new Date()) + ' · CoinGecko';
    } catch (err) {
      listEl.innerHTML = '<div class="skeleton" style="position:relative;height:120px;color:var(--danger)">Sin datos · API saturada</div>';
      updEl.textContent = 'Reintentando…';
    }
  }

  // ===================================================
  // INTEGRACIÓN 3 · NOTICIAS DE TECH/IA (Hacker News Algolia)
  // ===================================================
  async function fetchNews () {
    var listEl = document.getElementById('news-list');
    var updEl = document.getElementById('news-updated');

    var endpoints = [
      'https://hn.algolia.com/api/v1/search?tags=front_page&hitsPerPage=4',
      'https://hn.algolia.com/api/v1/search?query=AI&tags=story&hitsPerPage=4',
      'https://hn.algolia.com/api/v1/search_by_date?tags=story&hitsPerPage=4'
    ];

    for (var i = 0; i < endpoints.length; i++) {
      try {
        var r = await fetch(endpoints[i], { cache: 'no-store' });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        var j = await r.json();
        if (!j.hits || !j.hits.length) throw new Error('sin hits');

        var html = j.hits.slice(0, 4).map(function (h) {
          var safeTitle = escHTML(h.title || h.story_title || 'Sin título');
          var url = safeUrl(h.url || ('https://news.ycombinator.com/item?id=' + h.objectID));
          var pts = h.points || 0;
          var comments = h.num_comments || 0;
          var ago = h.created_at ? timeAgo(new Date(h.created_at)) : '';
          return '' +
            '<a class="news-item" href="' + escHTML(url) + '" target="_blank" rel="noopener noreferrer">' +
              '<div class="title">' + safeTitle + '</div>' +
              '<div class="meta">' +
                '<span>HN</span>' +
                (ago ? '<span>' + escHTML(ago) + '</span>' : '') +
                '<span class="pts">▲ ' + pts + ' pts</span>' +
                '<span>💬 ' + comments + '</span>' +
                '<span class="arr">↗</span>' +
              '</div>' +
            '</a>';
        }).join('');
        listEl.innerHTML = html;
        updEl.textContent = 'Actualizado ' + fmtTime(new Date()) + ' · HN Algolia';
        return; 
      } catch (err) {
        continue;
      }
    }

    listEl.innerHTML = '<div class="skeleton" style="position:relative;height:80px;color:var(--danger)">Sin datos del feed</div>';
    updEl.textContent = 'Reintentando…';
  }

  // ===================================================
  // Boot
  // ===================================================
  fetchDolar();
  fetchCrypto();
  fetchNews();
  setInterval(fetchDolar,  5 * 60 * 1000);  // cada 5 min
  setInterval(fetchCrypto, 60 * 1000);      // cada 60s
  setInterval(fetchNews,   5 * 60 * 1000);  // cada 5 min

  var resizeT;
  window.addEventListener('resize', function () {
    clearTimeout(resizeT);
    resizeT = setTimeout(function () {
      if (FX_DATA.length) {
        var vs = FX_DATA.map(function (p) { return p.valor; });
        drawFxChart(FX_DATA, Math.min.apply(null, vs), Math.max.apply(null, vs));
      }
    }, 200);
  });

  // ===================================================
  // PAGOS
  // ===================================================
  var plans = document.querySelectorAll('.plan');
  plans.forEach(function (p) {
    p.addEventListener('click', function () {
      plans.forEach(function (x) { x.classList.remove('is-selected'); });
      p.classList.add('is-selected');
      p.querySelector('input[type=radio]').checked = true;
    });
  });

  var FLOW_BUTTONS = {
    diagnostico: 'ndcfb9809e3432e30118961b4f66f68527fe4b4e',
    pack3:       null, 
    auditoria:   null, 
  };

  var btnPay = document.getElementById('btn-pay');
  var payErr = document.getElementById('pay-error');

  function showPayError (msg) {
    if (!payErr) return;
    payErr.textContent = msg;
    payErr.classList.add('is-visible');
  }
  function clearPayError () {
    if (!payErr) return;
    payErr.classList.remove('is-visible');
  }

  function flowUrlForPlan (planValue) {
    var token = FLOW_BUTTONS[planValue];
    if (!token) return null;
    return 'https://www.flow.cl/btn.php?token=' + encodeURIComponent(token);
  }

  function refreshPayButtonHref () {
    if (!btnPay) return;
    var selected = document.querySelector('.plan.is-selected') || document.querySelector('.plan');
    var input = selected ? selected.querySelector('input[type=radio]') : null;
    var planValue = input ? input.value : 'diagnostico';
    var url = flowUrlForPlan(planValue);

    if (url) {
      btnPay.setAttribute('href', url);
      clearPayError();
    } else {
      btnPay.setAttribute('href', '#');
      showPayError('Este plan aún no está disponible para pago en línea. Escribime a carlos@undersoftware.cl para coordinar.');
    }
  }

  if (btnPay) {
    refreshPayButtonHref();
    document.querySelectorAll('.plan').forEach(function (p) {
      p.addEventListener('click', refreshPayButtonHref);
    });

    btnPay.addEventListener('click', function (e) {
      if (btnPay.getAttribute('href') === '#') {
        e.preventDefault();
      }
    });
  }

  // ===================================================
  // Reveal on scroll
  // ===================================================
  var els = document.querySelectorAll('.reveal');
  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
      });
    }, { threshold: 0.1, rootMargin: '0px 0px -8% 0px' });
    els.forEach(function (el) { io.observe(el); });
  } else {
    els.forEach(function (el) { el.classList.add('in'); });
  }

})();