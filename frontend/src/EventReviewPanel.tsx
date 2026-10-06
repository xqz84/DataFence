import { useEffect, useRef, useState } from "react";
import { CheckCircle2, ClipboardCheck, LoaderCircle } from "lucide-react";
import { api, ApiError } from "./api";
import { Card, ErrorNotice, Loading, time, useApi } from "./ui";
import type { Disposition, EventReview } from "./workbenchTypes";

const DISPOSITIONS: Record<Disposition, string> = {
  confirmed_risk: "确认风险",
  false_positive: "研判为误报",
  needs_investigation: "继续调查",
};
export function EventReviewPanel({
  eventId,
  canReview,
  onReviewed,
}: {
  eventId: string;
  canReview: boolean;
  onReviewed?: (review: EventReview) => void;
}) {
  const [revision, setRevision] = useState(0);
  const review = useApi<EventReview>(
    `/events/${encodeURIComponent(eventId)}/review`,
    0,
    revision,
  );
  const [disposition, setDisposition] = useState<Disposition>(
    "needs_investigation",
  );
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const request = useRef<{ key: string; id: string } | null>(null);
  useEffect(() => {
    setNote("");
    setDisposition("needs_investigation");
    setError("");
    request.current = null;
  }, [eventId]);
  useEffect(() => {
    if (review.data) onReviewed?.(review.data);
  }, [review.data, onReviewed]);
  async function submit() {
    if (!canReview || saving || !note.trim() || !review.data) return;
    setSaving(true);
    setError("");
    const body = {
      expected_revision: review.data.revision,
      disposition,
      note: note.trim(),
    };
    const key = JSON.stringify({ eventId, ...body });
    if (request.current?.key !== key)
      request.current = { key, id: crypto.randomUUID() };
    try {
      const result = await api<EventReview>(
        `/events/${encodeURIComponent(eventId)}/review`,
        { body: { request_id: request.current.id, ...body } },
      );
      onReviewed?.(result);
      setRevision((value) => value + 1);
      setNote("");
      request.current = null;
    } catch (e) {
      setError(
        e instanceof ApiError && e.status === 409
          ? "研判版本已变化，已重新读取最新结论。请核对后再次提交。"
          : e instanceof Error
            ? e.message
            : "研判保存失败",
      );
      if (e instanceof ApiError && e.status === 409) {
        setRevision((value) => value + 1);
        request.current = null;
      }
    } finally {
      setSaving(false);
    }
  }
  return (
    <Card
      title="人工研判"
      subtitle="追加可追溯结论，不改变原始评分、阻断或额度，不授予权限"
      className="review-panel"
    >
      <ErrorNotice message={error || review.error} />
      {review.loading && <Loading />}
      {review.data?.current ? (
        <div className="review-current">
          <CheckCircle2 size={20} />
          <div>
            <strong>{DISPOSITIONS[review.data.current.disposition]}</strong>
            <p>{review.data.current.note}</p>
            <small>
              {review.data.current.actor} ·{" "}
              {time(review.data.current.created_at, true)} · 第{" "}
              {review.data.revision} 版
            </small>
          </div>
        </div>
      ) : (
        !review.loading && (
          <p className="workbench-muted">
            尚无人工结论。请先核对业务目的、命中依据与实际响应，再记录判断。
          </p>
        )
      )}
      {canReview ? (
        <form
          className="review-form"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <label>
            研判结论
            <select
              value={disposition}
              onChange={(e) => setDisposition(e.target.value as Disposition)}
              disabled={saving}
            >
              {Object.entries(DISPOSITIONS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label>
            判断依据
            <textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              maxLength={1000}
              rows={3}
              placeholder="记录业务核验结果与证据依据，不填写真实客户信息。"
              disabled={saving}
              required
            />
          </label>
          <div className="review-form-footer">
            <span className="workbench-muted">{note.length} / 1000 字</span>
            <button
              className="button primary"
              disabled={saving || !note.trim() || !review.data}
            >
              {saving ? (
                <LoaderCircle size={16} className="spin" />
              ) : (
                <ClipboardCheck size={16} />
              )}
              {saving ? "正在保存" : "保存研判结论"}
            </button>
          </div>
        </form>
      ) : (
        <p className="table-note">
          当前账号仅可查阅。管理员或分析员可以提交人工研判。
        </p>
      )}
      {!!review.data?.history.length && (
        <details className="model-details">
          <summary>查看研判历史 ({review.data.history.length})</summary>
          <ol className="review-history">
            {review.data.history.map((entry) => (
              <li key={entry.revision}>
                <strong>
                  第 {entry.revision} 版 · {DISPOSITIONS[entry.disposition]}
                </strong>
                <p>{entry.note}</p>
                <small>
                  {entry.actor} · {time(entry.created_at, true)}
                </small>
              </li>
            ))}
          </ol>
        </details>
      )}
    </Card>
  );
}
