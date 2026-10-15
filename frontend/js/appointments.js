// My Appointments (docs/scheduling.md): the appointments THIS browser booked from
// the chat. The chat and this page share the same origin, so the same
// localStorage `medadvice_client_id` identifies the browser; the page never
// mints one (an id only exists once the chat has run).

const CLIENT_ID_KEY = 'medadvice_client_id';
const THEME_LABELS = {
    medadvice: 'MedAdvice', taxadvice: 'TaxAdvice', benefitsadvice: 'BenefitsAdvice',
    legaladvice: 'LegalAdvice', financeadvice: 'FinanceAdvice', telecomchatbot: 'TelecomChatbot',
    retail: 'Retail', manufacturing: 'Manufacturing',
};
let currentStatus = 'scheduled';

// HTML escaping for server-provided values rendered via innerHTML.
function escHtml(s) {
    return String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function clientId() {
    try { return localStorage.getItem(CLIENT_ID_KEY) || ''; } catch (e) { return ''; }
}

function tzName() {
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { return ''; }
}

// Backend timestamps are naive UTC ISO strings; add the zone so Date() reads them as UTC.
function parseServerTime(s) {
    if (!s) return null;
    const str = String(s);
    return new Date(/(Z|[+-]\d\d:?\d\d)$/.test(str) ? str : str + 'Z');
}

document.addEventListener('DOMContentLoaded', () => {
    const filter = document.getElementById('statusFilter');
    if (filter) {
        filter.querySelectorAll('button[data-status]').forEach((btn) => {
            btn.addEventListener('click', () => {
                currentStatus = btn.dataset.status;
                filter.querySelectorAll('button[data-status]').forEach((b) => {
                    const on = b === btn;
                    b.className = 'px-3 py-1.5 text-sm font-semibold ' + (b !== filter.firstElementChild ? 'border-l border-gray-300 ' : '')
                        + (on ? 'bg-violet-600 text-white' : 'bg-white text-gray-700 hover:bg-gray-50');
                });
                loadAppointments();
            });
        });
    }
    loadAppointments();
    setInterval(loadAppointments, 30000);
});

function showEmpty(text) {
    const tbody = document.getElementById('appointmentsBody');
    const empty = document.getElementById('emptyState');
    if (tbody) tbody.innerHTML = '';
    if (empty) { empty.textContent = text; empty.classList.remove('hidden'); }
}

async function loadAppointments() {
    const tbody = document.getElementById('appointmentsBody');
    const empty = document.getElementById('emptyState');
    const cid = clientId();
    if (!cid) {
        showEmpty('No appointments yet — book one from the chat and it will appear here.');
        return;
    }
    try {
        const params = new URLSearchParams({ client_id: cid, status: currentStatus, tz: tzName(), limit: '200' });
        const response = await fetch('/api/appointments?' + params.toString());
        if (!response.ok) throw new Error('Failed to load appointments (' + response.status + ')');
        const data = await response.json();
        const rows = data.appointments || [];
        if (!rows.length) {
            showEmpty(currentStatus === 'scheduled'
                ? 'Nothing upcoming. Ask the chat to schedule an appointment.'
                : 'No appointments match this filter.');
            return;
        }
        if (empty) empty.classList.add('hidden');
        tbody.innerHTML = rows.map(renderRow).join('');
    } catch (e) {
        console.error('Error loading appointments:', e);
        showEmpty('Could not load appointments: ' + e.message);
    }
}

function renderRow(a) {
    const booked = parseServerTime(a.created_at);
    const status = a.status === 'cancelled'
        ? '<span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-gray-100 text-gray-600">Cancelled</span>'
        : '<span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-green-100 text-green-700">Scheduled</span>';
    const actions = a.status === 'cancelled'
        ? '<span class="text-xs text-gray-400">—</span>'
        : `<a href="/app" class="text-xs text-violet-600 hover:underline mr-3">Reschedule in chat</a>`
          + `<button type="button" data-id="${escHtml(a.id)}" onclick="cancelAppointment(this.dataset.id)" `
          + `class="px-2 py-1 text-xs bg-red-100 text-red-700 rounded hover:bg-red-200">Cancel</button>`;
    return `<tr class="border-b border-gray-100">
        <td class="px-4 py-2 text-sm font-semibold text-gray-800 whitespace-nowrap">${escHtml(a.label || a.start_utc)}</td>
        <td class="px-4 py-2 text-sm text-gray-700">${escHtml(THEME_LABELS[a.theme] || a.theme)}</td>
        <td class="px-4 py-2 text-sm text-gray-700">${escHtml(a.provider_label || '')}</td>
        <td class="px-4 py-2 text-sm text-gray-700">${escHtml(a.name || '—')}</td>
        <td class="px-4 py-2 text-sm">${status}</td>
        <td class="px-4 py-2 text-xs text-gray-500 whitespace-nowrap">${booked ? escHtml(booked.toLocaleString()) : '—'}</td>
        <td class="px-4 py-2 text-sm whitespace-nowrap">${actions}</td>
    </tr>`;
}

async function cancelAppointment(id) {
    if (!confirm('Cancel this appointment?')) return;
    try {
        const response = await fetch('/api/appointments/' + encodeURIComponent(id), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ client_id: clientId(), status: 'cancelled' }),
        });
        if (!response.ok) throw new Error('Cancel failed (' + response.status + ')');
        await loadAppointments();
    } catch (e) {
        console.error('Error cancelling appointment:', e);
        alert('Could not cancel that appointment. Please try again.');
    }
}
