import React, { useCallback, useEffect, useState } from 'react';
import api from '../../api/api';
import Button from '../ui/Button';

export default function ResponseAssist({ incidentId }) {
  const [data, setData] = useState(null);
  const [audit, setAudit] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const path = '/incidents/' + encodeURIComponent(incidentId) + '/response-proposals';
  const load = useCallback(async (signal) => {
    const result = await api.get(path, { signal });
    if (!signal?.aborted) setData(result);
  }, [path]);
  const pending = data?.actions.some(a => (['dispatched', 'executing', 'verifying'].includes(a.status) || a.rollback_available));
  useEffect(() => {
    const controller = new AbortController();
    const refresh = () => load(controller.signal).catch(e => {
      if (!controller.signal.aborted) setError(e.message);
    });
    refresh();
    const timer = pending && setInterval(refresh, 4000);
    return () => { clearInterval(timer); controller.abort(); };
  }, [load, pending]);

  async function run(operation, action) {
    if ((action?.proposed_ttl_seconds || action?.action_type === 'revoke_session') && ['approve', 'execute', 'rollback'].includes(operation) &&
        !window.confirm(operation + ' ' + action.action_type + '? ' + action.potential_impact)) return;
    setBusy(true);
    setError('');
    try {
      if (operation === 'propose') await api.post(path, { action_type: action.action_type });
      else {
        const endpoint = '/response-actions/' + encodeURIComponent(action.action_id);
        if (operation === 'audit') setAudit((await api.get(endpoint)).audit);
        else await api.post(endpoint + '/' + operation, {});
      }
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const investigation = data?.investigation;
  return <section>
    <h3>AI Response Assist</h3>
    {error && <p role="alert">{error}</p>}
    {data && !investigation && <p>Correlated HTTP evidence required.</p>}
    {investigation && <>
      <p><strong>{investigation.classification}</strong> · Rule confidence {Math.round(investigation.confidence * 100)}% · Evidence {investigation.evidence_completeness}</p>
      <p>{investigation.behavioral_interpretation}</p>
      <details><summary>View evidence</summary>
        {investigation.observed_facts.map(f => <p key={f.evidence_ids[0]}>
          {f.provenance} · {f.evidence_ids[0]} · {f.observed_at} · {f.method} · HTTP {f.http_status} · {f.source_ip} · {f.automation_hint} {f.payload_indicators?.join(', ')} {f.outcome}
        </p>)}
        <p>Missing evidence · {investigation.missing_evidence.join(', ')}</p>
      </details>
      {investigation.recommended_responses.map(candidate =>
        <Button key={candidate.action_id} disabled={busy} onClick={() => run('propose', candidate)}>
          Review {candidate.action_type.replaceAll('_', ' ')}
        </Button>)}
    </>}
    {data?.actions.map(action => <article key={action.action_id}>
      <h4>{action.action_type.replaceAll('_', ' ')}</h4>
      <p>{action.expected_effect} {action.potential_impact}</p>
      <p>{action.recommendation_source} · {action.policy_decision} · <strong>{action.status}</strong></p>
      {action.result.verification && <p>Verification · {action.result.verification.method} · {action.result.verification.status} · {action.result.verification.evidence_refs.join(', ')}</p>}
      {action.result.related_records && <details><summary>Collected records</summary><pre>{JSON.stringify(action.result.related_records, null, 2)}</pre></details>}
      <p>Rollback · {action.rollback_strategy}</p>
      {(action.status === 'pending_approval' ? ['approve', 'reject', 'audit'] :
        action.status === 'approved' ? ['execute', 'audit'] : action.rollback_available ? ['rollback', 'audit'] : ['audit']).map(op =>
        <Button key={op} disabled={busy} onClick={() => run(op, action)}>{op === 'audit' ? 'View audit trail' : op}</Button>
      )}
    </article>)}
    {audit && <ol>{audit.map((r, i) => <li key={i}>{r.at} · {r.actor} · {r.event}</li>)}</ol>}
  </section>;
}
