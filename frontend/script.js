const API = "http://localhost:8000";

// Live popup for high-severity threats
const evtSource = new EventSource(API + "/live");
evtSource.onmessage = function (event) {
  const data = JSON.parse(event.data);
  if (data.threat && data.severity == "high")
    showThreatPopup(`${data.src_ip} → ${data.dst_ip} [${data.note || ''}]`);
};

function showThreatPopup(message) {
  const popup = document.createElement("div");
  popup.className = "popup";
  popup.innerText = "🚨 " + message;
  document.body.appendChild(popup);
  setTimeout(() => popup.remove(), 5000);
}

// Graph rendering
async function fetchGraph() {
  const res = await fetch(API + "/graph");
  const json = await res.json();
  const elements = [];
  json.nodes.forEach(n => elements.push({ data: { id: n.id, label: n.id } }));
  json.edges.forEach(e => elements.push({ data: { id: e.source + '_' + e.target, source: e.source, target: e.target, count: e.count } }));
  renderGraph(elements);
}
function renderGraph(elements) {
  const cy = cytoscape({
    container: document.getElementById('graph'),
    elements: elements,
    style: [
      {
        selector: 'node',
        style: {
          'background-color': '#3b82f6',
          'background-opacity': 0.9,
          'label': 'data(label)',
          'color': '#e0e7ff',
          'text-valign': 'bottom',
          'text-halign': 'center',
          'text-margin-y': 8,
          'font-size': '11px',
          'font-weight': '500',
          'width': 28,
          'height': 28,
          'border-width': 2,
          'border-color': '#60a5fa',
          'text-outline-color': '#0b1220',
          'text-outline-width': 2
        }
      },
      {
        selector: 'edge',
        style: {
          'width': 1.5,
          'line-color': 'rgba(200, 210, 230, 0.6)',
          'target-arrow-color': 'rgba(200, 210, 230, 0.6)',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'arrow-scale': 0.8
        }
      }
    ],
    layout: {
      name: 'cose',
      animate: true,
      animationDuration: 500,
      nodeRepulsion: 8000,
      idealEdgeLength: 100,
      gravity: 0.25
    }
  });
}

// Event panel
async function refreshEvents() {
  const res = await fetch(API + "/events");
  const events = await res.json();
  const panel = document.getElementById("events");
  panel.innerHTML = "";
  events.forEach(ev => {
    const div = document.createElement("div");
    div.className = ev.threat ? "event threat" : "event safe";
    div.innerHTML = `
        <strong>${ev.src_ip}</strong> → <strong>${ev.dst_ip}</strong>
        (${ev.protocol}) | Port: ${ev.dst_port || '-'} | Threat: ${ev.threat ? "YES" : "NO"} | Severity: ${ev.severity || 'low'}
    `;
    panel.appendChild(div);
  });
}

// Buttons
document.getElementById('refreshBtn').addEventListener('click', () => { fetchGraph(); refreshEvents(); });
document.getElementById('sampleEventBtn').addEventListener('click', async () => {
  const payload = { src_ip: "10.0.0.1", dst_ip: "10.0.0.5", dst_port: 22, protocol: "TCP", bytes: 1234, payload_hash: "deadbeef" };
  await fetch(API + "/ingest", { method: "POST", headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  await fetchGraph(); await refreshEvents();
});

// SIEM tools
function checkIPReputation(ip) {
  fetch(API + "/events").then(r => r.json()).then(events => {
    const threat = events.some(ev => ev.src_ip === ip && ev.threat);
    alert(`${ip} is ${threat ? "a threat" : "safe"}`);
  });
}
function checkPort(port) {
  fetch(API + "/events").then(r => r.json()).then(events => {
    const threat = events.some(ev => ev.dst_port == port && ev.threat);
    alert(`Port ${port} is ${threat ? "risky" : "safe"}`);
  });
}
function checkHash(hash) {
  fetch(API + "/events").then(r => r.json()).then(events => {
    const threat = events.some(ev => ev.payload_hash === hash && ev.threat);
    alert(`Hash ${hash} is ${threat ? "malicious" : "safe"}`);
  });
}

// initial load
fetchGraph();
refreshEvents();
