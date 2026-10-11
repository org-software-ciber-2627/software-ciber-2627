const SIEM_URL = "../mocks/alerts-SIEM.json";

export async function getAlerts() {
  const r = await fetch(SIEM_URL);
  if (!r.ok) throw new Error(r.status);
  const data = await r.json();
  return data.alerts;
}