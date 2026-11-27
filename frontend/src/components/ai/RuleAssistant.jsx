import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { FiSend, FiCpu, FiUser, FiPlay, FiCheckCircle, FiExternalLink } from 'react-icons/fi';
import api from '../../api/api';
import ValidationResultPanel from './ValidationResultPanel';

// Natural-language rule creation: the model only fills the intent; answers and the rule itself are
// deterministic on the Manager. Values the analyst did not write are dropped and asked back.
const EXAMPLES = [
  'Báo động khi web app vulnerable_web/app.py trên Linux sinh shell và có chèn lệnh như ; hoặc &&',
  'Báo khi web server sinh bash chạy whoami hoặc curl',
  'Báo khi có tiến trình chạy vssadmin delete shadows trên Windows',
];
const FIELDS = [
  ['parent', 'Tiến trình cha'], ['child', 'Tiến trình cần phát hiện'], ['command', 'Từ khóa trong lệnh'],
];

const emptyIntent = {
  platform: null, parent: [], parent_hint: null, child: [], command: [], chaining: false,
  severity: 'medium', mitre: [], title: null,
};

const box = { background: '#0d1117', border: '1px solid #30363d', borderRadius: '0.5rem', padding: '1rem' };
const chip = {
  padding: '0.3rem 0.7rem', borderRadius: '999px', border: '1px solid #3b82f6', background: 'rgba(59,130,246,0.1)',
  color: '#93c5fd', fontSize: '0.8rem', cursor: 'pointer',
};

// Backend classification of the latest turn, shown in words with the raw code for traceability.
const CLASSIFICATION = {
  READY_TO_GENERATE: ['Đủ thông tin: rule đã được biên dịch', '#3fb950'],
  NEEDS_CLARIFICATION: ['Cần bạn trả lời thêm trước khi tạo rule', '#d29922'],
  UNSUPPORTED_REQUIREMENT: ['Sigma process_creation không biểu diễn được yêu cầu này', '#f85149'],
  INSUFFICIENT_TELEMETRY: ['Thiếu nguồn dữ liệu để phát hiện', '#f85149'],
};

export default function RuleAssistant() {
  const navigate = useNavigate();
  const [messages, setMessages] = useState([]);
  const [conversation, setConversation] = useState(null);
  const [classification, setClassification] = useState('');
  const [input, setInput] = useState('');
  const [intent, setIntent] = useState(emptyIntent);
  const [questions, setQuestions] = useState([]);
  const [sigmaYaml, setSigmaYaml] = useState(null);
  const [loading, setLoading] = useState(false);
  const [modelUsed, setModelUsed] = useState(false);
  const [created, setCreated] = useState(null);
  const [answerText, setAnswerText] = useState('');

  const userTexts = messages.filter((m) => m.role === 'user').map((m) => m.text);

  const say = (text, role = 'assistant') => setMessages((prev) => [...prev, { role, text }]);

  const apply = (res) => {
    if (res.conversation_id) {
      setConversation({ conversation_id: res.conversation_id, revision: res.revision });
      sessionStorage.setItem('harvest-conversation', res.conversation_id);
    }
    setClassification(res.classification);
    setIntent(res.intent);
    setQuestions(res.questions || []);
    setSigmaYaml(res.sigma_yaml);
    setModelUsed(Boolean(res.has_model_input || res.model_used));
    const lines = [];
    if (res.error) lines.push(res.error);
    (res.notices || []).forEach((n) => lines.push(n));
    if (res.ready) lines.push('Đã đủ thông tin. Kiểm tra rule bên dưới rồi bấm "Tạo rule & bắt đầu giám sát".');
    else if (res.questions?.length) lines.push(res.questions[0].text);
    if (lines.length) say(lines.join('\n'));
  };

  useEffect(() => {
    const id = sessionStorage.getItem('harvest-conversation');
    if (!id) return;
    let mounted = true;
    setLoading(true);
    api.post('/rules/assistant', { conversation_id: id, resume: true })
      .then(res => {
        if (mounted) {
          setMessages(res.context ? [{ role: 'user', text: res.context }] : []);
          apply(res);
        }
      })
      .catch(err => { if (mounted) say(err.message); })
      .finally(() => { if (mounted) setLoading(false); });
    return () => { mounted = false; };
  }, []);

  const reset = () => {
    sessionStorage.removeItem('harvest-conversation');
    setConversation(null); setMessages([]); setQuestions([]); setIntent(emptyIntent);
    setClassification(''); setSigmaYaml(null); setCreated(null); setModelUsed(false); setAnswerText(''); setInput('');
  };

  const call = async (body) => {
    setLoading(true);
    try {
      apply(await api.post('/rules/assistant', { ...body, ...conversation }));
    } catch (err) {
      say(`Lỗi: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const send = async (text) => {
    const message = (text ?? input).trim();
    if (!message || loading) return;
    setInput('');
    setCreated(null);
    say(message, 'user');
    await call({ message, context: userTexts.join('\n'), intent });
  };

  const answer = async (question, value) => {
    if (!value || loading) return;
    say(Array.isArray(value) ? value.join(', ') : value, 'user');
    setAnswerText('');
    await call({ intent, answer: { slot: question.slot, value, replace: question.replace || null } });
  };

  const editField = (key, text) =>
    setIntent((prev) => ({ ...prev, [key]: text.split(',').map((v) => v.trim()).filter(Boolean) }));

  const recheck = () => call({ intent });

  const create = async () => {
    setLoading(true);
    try {
      const res = await api.post('/rules/assistant/create', {
        ...conversation, intent, description: userTexts.join('\n'), model_used: modelUsed,
      });
      setCreated(res);
      say(`Đã tạo rule "${res.rule_name}" ở chế độ giám sát. ${res.promotion?.reason || ''}`);
    } catch (err) {
      toast.error(err.message);
    } finally {
      setLoading(false);
    }
  };

  const promote = async () => {
    try {
      const res = await api.post(`/rules/${created.rule_id}/activate`, {});
      if (res.error) return toast.error(res.error);
      toast.success('Rule đã chạy chính thức: lần khớp mới sẽ tạo incident');
      setCreated({ ...created, status: res.status });
    } catch (err) {
      toast.error(err.message);
    }
  };

  const question = questions[0];
  const preview = created?.recent_telemetry;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.1fr) minmax(0, 1fr)', gap: '1rem' }}>
      {/* Conversation */}
      <div style={{ ...box, display: 'flex', flexDirection: 'column', gap: '0.75rem', minHeight: '28rem' }}>
        <div style={{ color: '#e6edf3', fontWeight: 600 }}>Mô tả rule bằng lời</div>
        {conversation && <button disabled={loading} onClick={reset} className="harvest-btn-secondary">Yêu cầu mới</button>}
        {classification && (
          <div data-testid="harvest-classification"
               style={{ fontSize: '0.8rem', color: (CLASSIFICATION[classification] || [])[1] || '#8b949e' }}>
            {(CLASSIFICATION[classification] || [classification])[0]} <code style={{ color: '#8b949e' }}>({classification})</code>
          </div>
        )}
        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '26rem' }}>
          {messages.length === 0 && (
            <div style={{ color: '#8b949e', fontSize: '0.85rem' }}>
              Gõ điều bạn muốn phát hiện. AI chỉ trích thông tin; nếu thiếu hoặc chưa rõ, trợ lý sẽ hỏi lại. Ví dụ:
              {EXAMPLES.map((e) => (
                <button key={e} onClick={() => send(e)} disabled={loading}
                        style={{ ...chip, display: 'block', marginTop: '0.5rem', borderRadius: '0.4rem', textAlign: 'left' }}>
                  {e}
                </button>
              ))}
            </div>
          )}
          {messages.map((m, i) => (
            <div key={i} style={{ display: 'flex', gap: '0.5rem', alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
                                   maxWidth: '90%' }}>
              {m.role !== 'user' && <FiCpu style={{ color: '#a78bfa', marginTop: '0.2rem', flexShrink: 0 }} />}
              <div style={{ whiteSpace: 'pre-wrap', fontSize: '0.85rem', padding: '0.5rem 0.75rem', borderRadius: '0.5rem',
                            background: m.role === 'user' ? '#1f6feb33' : '#161b22', color: '#e6edf3' }}>
                {m.text}
              </div>
              {m.role === 'user' && <FiUser style={{ color: '#58a6ff', marginTop: '0.2rem', flexShrink: 0 }} />}
            </div>
          ))}
          {loading && <div style={{ color: '#8b949e', fontSize: '0.8rem' }}>Đang xử lý… (AI chạy trên CPU có thể mất khoảng 1 phút)</div>}
        </div>

        {question && !loading && (
          <div style={{ borderTop: '1px solid #30363d', paddingTop: '0.6rem' }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', marginBottom: '0.4rem' }}>
              {(question.options || []).map((opt) => (
                <button key={opt} style={chip} onClick={() => answer(question, opt)}>{opt}</button>
              ))}
            </div>
            {question.allow_text && (
              <div style={{ display: 'flex', gap: '0.4rem' }}>
                <input value={answerText} onChange={(e) => setAnswerText(e.target.value)}
                       onKeyDown={(e) => e.key === 'Enter' && answer(question, answerText.trim())}
                       placeholder="Trả lời (nhiều giá trị cách nhau bằng dấu phẩy)"
                       style={{ flex: 1, background: '#010409', border: '1px solid #30363d', color: '#e6edf3',
                                borderRadius: '0.4rem', padding: '0.4rem 0.6rem', fontSize: '0.85rem' }} />
                <button className="harvest-btn-secondary" onClick={() => answer(question, answerText.trim())}>Trả lời</button>
              </div>
            )}
          </div>
        )}

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <textarea value={input} onChange={(e) => setInput(e.target.value)} rows={2}
                    onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } }}
                    placeholder="Ví dụ: báo khi nginx sinh shell chạy whoami"
                    style={{ flex: 1, background: '#010409', border: '1px solid #30363d', color: '#e6edf3',
                             borderRadius: '0.4rem', padding: '0.5rem', fontSize: '0.85rem', resize: 'vertical' }} />
          <button className="harvest-btn-activate" onClick={() => send()} disabled={loading || !input.trim()}>
            <FiSend size={14} />
          </button>
        </div>
      </div>

      {/* Understood intent, compiled rule, result */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={box}>
          <div style={{ color: '#e6edf3', fontWeight: 600, marginBottom: '0.6rem' }}>AI đã hiểu (có thể sửa)</div>
          <div style={{ display: 'grid', gridTemplateColumns: '9rem 1fr', gap: '0.45rem', fontSize: '0.82rem', alignItems: 'center' }}>
            <label style={{ color: '#8b949e' }}>Nền tảng</label>
            <select value={intent.platform || ''} onChange={(e) => setIntent({ ...intent, platform: e.target.value || null })}
                    style={{ background: '#010409', color: '#e6edf3', border: '1px solid #30363d', borderRadius: '0.3rem', padding: '0.25rem' }}>
              <option value="">Chưa rõ</option><option value="linux">Linux</option><option value="windows">Windows</option>
            </select>
            {FIELDS.map(([key, label]) => (
              <React.Fragment key={key}>
                <label style={{ color: '#8b949e' }}>{label}</label>
                <input value={(intent[key] || []).join(', ')} onChange={(e) => editField(key, e.target.value)}
                       placeholder={key === 'parent' && intent.parent_hint ? `chưa rõ: ${intent.parent_hint}` : 'trống'}
                       style={{ background: '#010409', color: '#e6edf3', border: '1px solid #30363d', borderRadius: '0.3rem', padding: '0.25rem 0.4rem' }} />
              </React.Fragment>
            ))}
            <label style={{ color: '#8b949e' }}>Nối lệnh (; | && $())</label>
            <input type="checkbox" checked={!!intent.chaining} onChange={(e) => setIntent({ ...intent, chaining: e.target.checked })}
                   style={{ justifySelf: 'start' }} />
            <label style={{ color: '#8b949e' }}>Mức độ</label>
            <select value={intent.severity} onChange={(e) => setIntent({ ...intent, severity: e.target.value })}
                    style={{ background: '#010409', color: '#e6edf3', border: '1px solid #30363d', borderRadius: '0.3rem', padding: '0.25rem' }}>
              {['low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <button className="harvest-btn-secondary" style={{ marginTop: '0.7rem' }} onClick={recheck} disabled={loading}>
            Cập nhật & kiểm tra
          </button>
        </div>

        {sigmaYaml && (
          <div style={box}>
            <div style={{ color: '#e6edf3', fontWeight: 600, marginBottom: '0.4rem' }}>Rule sẽ được tạo (do hệ thống sinh, không phải AI)</div>
            <pre style={{ fontSize: '0.75rem', color: '#c9d1d9', whiteSpace: 'pre-wrap', margin: 0 }}>{sigmaYaml}</pre>
            {!created && (
              <button className="harvest-btn-activate" style={{ marginTop: '0.7rem' }} onClick={create} disabled={loading}>
                <FiPlay size={13} /> Tạo rule & bắt đầu giám sát
              </button>
            )}
          </div>
        )}

        {created && (
          <div style={{ ...box, display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
              <strong style={{ color: created.status === 'active' ? '#2dd4bf' : '#fbbf24' }}>
                {created.status === 'active' ? 'Đang chạy chính thức' : 'Đang giám sát (chưa tạo incident)'}
              </strong>
              <button className="harvest-btn-secondary" onClick={() => navigate(`/ai-dashboard/rules/${created.rule_id}`)}>
                Chi tiết rule <FiExternalLink size={12} />
              </button>
            </div>
            {preview && (
              <div style={{ fontSize: '0.82rem', color: '#c9d1d9' }}>
                Chạy thử trên telemetry thật {preview.hours} giờ qua ({preview.processes_scanned} tiến trình, {preview.snapshots} snapshot,
                không có nhãn): <strong>{preview.matches} lần khớp</strong>
                {preview.samples?.map((s) => (
                  <div key={`${s.agent_id}-${s.pid}-${s.cmdline}`} style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: '#8b949e' }}>
                    {s.agent_id} · pid {s.pid} · {s.cmdline}
                  </div>
                ))}
              </div>
            )}
            <ValidationResultPanel result={created.validation_result} />
            {created.status !== 'active' && (
              <div style={{ fontSize: '0.82rem', color: created.promotion?.allowed ? '#34d399' : '#fca5a5' }}>
                {created.promotion?.reason}
                {created.promotion?.allowed && (
                  <button className="harvest-btn-activate" style={{ marginLeft: '0.75rem' }} onClick={promote}>
                    <FiCheckCircle size={13} /> Bật chính thức
                  </button>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
