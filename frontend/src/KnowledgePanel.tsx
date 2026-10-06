import { useEffect, useRef, useState } from "react";
import { BookOpen, Search, X } from "lucide-react";
import { api } from "./api";
import { Card, Empty, ErrorNotice, Loading, useApi } from "./ui";
import type {
  KnowledgeDocument,
  KnowledgeHit,
  KnowledgeSearch,
  KnowledgeStatus,
} from "./workbenchTypes";

export function KnowledgePanel({
  related = [],
  documentId = "",
  onDocumentChange,
}: {
  related?: KnowledgeHit[];
  documentId?: string;
  onDocumentChange: (id: string) => void;
}) {
  const status = useApi<KnowledgeStatus>("/knowledge/status");
  const documents = useApi<Omit<KnowledgeDocument, "content">[]>(
    "/knowledge/documents",
  );
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<KnowledgeSearch | null>(null);
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState("");
  const controller = useRef<AbortController | null>(null);
  const document = useApi<KnowledgeDocument>(
    documentId
      ? `/knowledge/documents/${encodeURIComponent(documentId)}`
      : null,
  );
  useEffect(() => () => controller.current?.abort(), []);
  async function search(value = query) {
    if (!value.trim()) return;
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setQuery(value);
    setSearching(true);
    setError("");
    setResult(null);
    try {
      setResult(
        await api<KnowledgeSearch>(
          `/knowledge/search?q=${encodeURIComponent(value.trim())}&limit=5`,
          { signal: current.signal },
        ),
      );
    } catch (e) {
      if (!current.signal.aborted)
        setError(e instanceof Error ? e.message : "检索失败");
    } finally {
      if (!current.signal.aborted) setSearching(false);
    }
  }
  return (
    <Card
      title="项目知识库"
      subtitle={`${status.data ? `${status.data.document_count} 条项目条款 · ` : ""}本地检索，可展开正文核对依据`}
      className="knowledge-panel"
    >
      <p className="workbench-muted">
        内容为项目沙盒政策与工程说明，不是银行内部制度或法律意见。检索不会改变权限，也不是模型训练。
      </p>
      <form
        className="knowledge-search"
        onSubmit={(e) => {
          e.preventDefault();
          void search();
        }}
      >
        <label className="sr-only" htmlFor="knowledge-query">
          检索项目知识库
        </label>
        <input
          id="knowledge-query"
          maxLength={200}
          placeholder="例如：超出工单额度为什么不能查询？"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <button
          className="button primary"
          disabled={searching || !query.trim()}
        >
          <Search size={16} />
          {searching ? "检索中" : "检索条款"}
        </button>
      </form>
      <div className="knowledge-suggestions">
        {["工单额度", "AI 请求", "导出授权", "证据链"].map((text) => (
          <button
            key={text}
            type="button"
            onClick={() => void search(text)}
            disabled={searching}
          >
            {text}
          </button>
        ))}
      </div>
      <ErrorNotice
        message={error || status.error || documents.error || document.error}
      />
      {searching && <Loading />}
      {result && (
        <div className="knowledge-answer" aria-live="polite">
          <strong>
            {result.answered ? "检索到相关项目依据" : "没有足够可靠的项目依据"}
          </strong>
          <p>
            {result.answer ||
              "当前知识库无法回答这个问题。请改用具体的工单、数据流转或审计问题；系统不会补写不存在的规定。"}
          </p>
        </div>
      )}
      {result?.matches.length || (!result && related.length) ? (
        <div className="knowledge-results">
          <span className="section-caption">
            {result ? "检索结果" : "当前事件关联条款"}
          </span>
          {(result ? result.matches : related).map((hit) => (
            <button
              key={hit.id}
              className={`knowledge-hit ${documentId === hit.id ? "selected" : ""}`}
              onClick={() => onDocumentChange(hit.id)}
            >
              <BookOpen size={17} />
              <span>
                <strong>{hit.title}</strong>
                <small>{hit.excerpt}</small>
                <em>
                  {hit.source_title} · {hit.version}
                </em>
              </span>
            </button>
          ))}
        </div>
      ) : null}
      {documentId && (
        <div className="knowledge-document">
          <div className="knowledge-document-top">
            <strong>条款正文</strong>
            <button
              type="button"
              className="icon-button"
              aria-label="关闭条款正文"
              onClick={() => onDocumentChange("")}
            >
              <X size={17} />
            </button>
          </div>
          {document.loading ? (
            <Loading />
          ) : (
            document.data && (
              <>
                <h3>{document.data.title}</h3>
                <p className="workbench-muted">
                  {document.data.source_title} · {document.data.version}
                </p>
                <div className="knowledge-content">{document.data.content}</div>
                <details className="model-details">
                  <summary>条款来源与完整性摘要</summary>
                  <dl className="evidence-values">
                    <dt>来源引用</dt>
                    <dd>{document.data.source_ref}</dd>
                    <dt>SHA-256</dt>
                    <dd className="mono">{document.data.sha256}</dd>
                  </dl>
                </details>
              </>
            )
          )}
        </div>
      )}
      <details className="model-details">
        <summary>
          浏览全部项目条款 {documents.data ? `(${documents.data.length})` : ""}
        </summary>
        <div className="knowledge-directory">
          {documents.data?.map((doc) => (
            <button key={doc.id} onClick={() => onDocumentChange(doc.id)}>
              <BookOpen size={14} />
              {doc.title}
            </button>
          ))}
        </div>
        {documents.loading && <Loading />}
        {documents.data?.length === 0 && (
          <Empty title="知识条款尚未载入" text="以服务端实际提供的文档为准。" />
        )}
      </details>
    </Card>
  );
}
