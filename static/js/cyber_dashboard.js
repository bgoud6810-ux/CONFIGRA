/**
 * static/js/cyber_dashboard.js
 * Results Dashboard interactions: finding filters and detail view modal.
 */
(function () {
  function qs(sel, root) { return (root || document).querySelector(sel); }
  function qsa(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function openModalFromRow(row) {
    var modal = qs('#findingModal');
    if (!modal || !row) return;
    var sev = row.getAttribute('data-severity') || 'Info';
    var title = row.getAttribute('data-title') || 'Finding details';
    var evidence = row.getAttribute('data-evidence') || 'No evidence provided.';
    var url = row.getAttribute('data-url') || 'N/A';
    var fix = row.getAttribute('data-fix') || 'No remediation details provided.';
    var id = row.getAttribute('data-id') || '';
    var cat = row.getAttribute('data-category') || '';
    var conf = row.getAttribute('data-confidence') || '';

    qs('#findingModalTitle').textContent = title;
    var sevEl = qs('#mSev');
    sevEl.textContent = sev;
    sevEl.className = 'db-sev-badge sev-b-' + String(sev).toLowerCase();
    qs('#mId').textContent = id;
    qs('#mCat').textContent = cat ? ('Category: ' + cat) : '';
    qs('#mConf').textContent = conf ? ('Confidence: ' + conf) : '';
    qs('#mEvidence').textContent = evidence;
    qs('#mUrl').textContent = url || 'N/A';
    qs('#mFix').textContent = fix;

    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
  }

  function closeModal() {
    var modal = qs('#findingModal');
    if (!modal) return;
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
  }

  function filterFindings(severity) {
    var rows = qsa('#findingsTable tbody tr.finding-row');
    var btns = qsa('.filter-btn');
    btns.forEach(function (btn) {
      var f = btn.getAttribute('data-filter') || btn.textContent || '';
      var active = (severity === 'all' && /all/i.test(f)) || f === severity;
      btn.classList.toggle('active', !!active);
    });
    rows.forEach(function (row) {
      var s = row.getAttribute('data-severity') || '';
      row.style.display = (severity === 'all' || s === severity) ? '' : 'none';
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    // Expose for any legacy inline handlers
    window.filterFindings = filterFindings;

    qsa('.filter-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var sev = btn.getAttribute('data-filter');
        if (!sev) {
          var t = (btn.textContent || '').trim().toLowerCase();
          sev = t.indexOf('all') === 0 ? 'all' : (btn.textContent || '').trim().split(' ')[0];
        }
        filterFindings(sev || 'all');
      });
    });

    qsa('.view-finding-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        openModalFromRow(btn.closest('tr.finding-row'));
      });
    });

    qsa('[data-close="1"]').forEach(function (el) {
      el.addEventListener('click', closeModal);
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') closeModal();
    });
  });
})();
