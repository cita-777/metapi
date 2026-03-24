import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { MobileCard, MobileField } from "../components/MobileCard.js";
import ResponsiveFilterPanel from "../components/ResponsiveFilterPanel.js";
import { useToast } from "../components/Toast.js";
import { useIsMobile } from "../components/useIsMobile.js";
import {
  formatCheckinLogTime,
  parseServerUtcDateTime,
} from "./helpers/checkinLogTime.js";
import { tr } from "../i18n.js";

type LogFilter = "all" | "success" | "failed" | "skipped";

type FailureReason = {
  code: string;
  category: string;
  title: string;
  actionHint: string;
  detailHint: string;
};

function pad2(value: number) {
  return String(value).padStart(2, "0");
}

function formatDateTimeInputValue(value: Date) {
  return `${value.getFullYear()}-${pad2(value.getMonth() + 1)}-${pad2(value.getDate())}T${pad2(value.getHours())}:${pad2(value.getMinutes())}`;
}

function getTodayTimeRangeInput(now = new Date()): {
  from: string;
  to: string;
} {
  const start = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate(),
    0,
    0,
    0,
    0,
  );
  const end = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate(),
    23,
    59,
    0,
    0,
  );
  return {
    from: formatDateTimeInputValue(start),
    to: formatDateTimeInputValue(end),
  };
}

function parseLocalDateTimeInput(value: string): Date | null {
  const text = value.trim();
  if (!text) return null;
  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed;
}

export default function CheckinLog() {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [triggering, setTriggering] = useState(false);
  const [filter, setFilter] = useState<LogFilter>("all");
  const [expandedLogId, setExpandedLogId] = useState<number | null>(null);
  const [showFilters, setShowFilters] = useState(false);
  const isMobile = useIsMobile();
  const toast = useToast();

  function getStatus(log: any): "success" | "failed" | "skipped" {
    const raw = (log.checkin_logs?.status || log.status || "failed") as string;
    if (raw === "success" || raw === "skipped") return raw;
    return "failed";
  }

  function getCreatedAtDate(log: any): Date | null {
    const createdAt = log.checkin_logs?.createdAt || log.createdAt;
    return parseServerUtcDateTime(createdAt);
  }

  const initialTimeRange = useMemo(() => getTodayTimeRangeInput(), []);
  const [fromInput, setFromInput] = useState(initialTimeRange.from);
  const [toInput, setToInput] = useState(initialTimeRange.to);

  const fromRaw = useMemo(
    () => parseLocalDateTimeInput(fromInput),
    [fromInput],
  );
  const toRaw = useMemo(() => parseLocalDateTimeInput(toInput), [toInput]);
  const fromMs = fromRaw?.getTime() ?? null;
  const toMs = toRaw?.getTime() ?? null;
  const toExclusiveMs = toMs === null ? null : toMs + 60_000;

  const hasInvalidTimeRange = Boolean(
    fromMs !== null && toMs !== null && fromMs >= toMs,
  );

  const timeFilteredLogs = useMemo(() => {
    if (hasInvalidTimeRange) return [];

    return logs.filter((log) => {
      const createdAtDate = getCreatedAtDate(log);
      if (!createdAtDate) return false;

      const createdAtMs = createdAtDate.getTime();
      if (fromMs !== null && createdAtMs < fromMs) return false;
      if (toExclusiveMs !== null && createdAtMs >= toExclusiveMs) return false;
      return true;
    });
  }, [fromMs, hasInvalidTimeRange, logs, toExclusiveMs]);

  const statusFilteredLogs = useMemo(
    () =>
      filter === "all"
        ? timeFilteredLogs
        : timeFilteredLogs.filter((log) => getStatus(log) === filter),
    [filter, timeFilteredLogs],
  );

  // 兼容旧命名：后面渲染统一用 filtered
  const filtered = statusFilteredLogs;

  const countBy = useMemo(
    () => (target: Exclude<LogFilter, "all">) =>
      timeFilteredLogs.filter((log) => getStatus(log) === target).length,
    [timeFilteredLogs],
  );

  const clearTimeRange = () => {
    setFromInput("");
    setToInput("");
  };

  const load = async () => {
    setLoading(true);
    try {
      const data = await api.getCheckinLogs("limit=100");
      setLogs(Array.isArray(data) ? data : []);
    } catch (e: any) {
      toast.error(e.message || "加载签到记录失败");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleTriggerAll = async () => {
    setTriggering(true);
    try {
      const res = await api.triggerCheckinAll();
      if (res?.queued) {
        toast.info(res.message || "已开始签到，请稍后查看签到记录");
      } else {
        toast.success(res?.message || "签到已执行");
      }
      await load();
    } catch (e: any) {
      toast.error(e.message || "触发签到失败");
    } finally {
      setTriggering(false);
    }
  };

  const statusLabel = (status: "success" | "failed" | "skipped") => {
    if (status === "success") return "成功";
    if (status === "skipped") return "跳过";
    return "失败";
  };

  const statusClass = (status: "success" | "failed" | "skipped") => {
    if (status === "success") return "badge-success";
    if (status === "skipped") return "badge-muted";
    return "badge-error";
  };

  const getFailureReason = (log: any): FailureReason | null => {
    const reason = log.failureReason as FailureReason | undefined;
    if (!reason || !reason.code) return null;
    return reason;
  };

  const timeRangeControls = (
    <div
      style={{
        display: "flex",
        flexWrap: "wrap",
        gap: 10,
        alignItems: "center",
      }}
    >
      <label className="proxy-logs-time-field">
        <span>开始</span>
        <input
          type="datetime-local"
          value={fromInput}
          max={toInput || undefined}
          onChange={(e) => setFromInput(e.target.value)}
        />
      </label>
      <label className="proxy-logs-time-field">
        <span>结束</span>
        <input
          type="datetime-local"
          value={toInput}
          min={fromInput || undefined}
          onChange={(e) => setToInput(e.target.value)}
        />
      </label>
      <button
        type="button"
        className="btn btn-ghost proxy-logs-filter-reset"
        onClick={clearTimeRange}
      >
        清空筛选
      </button>
    </div>
  );

  const filterTabs = (
    <div className="pill-tabs">
      {[
        { key: "all" as const, label: "全部", count: timeFilteredLogs.length },
        { key: "success" as const, label: "成功", count: countBy("success") },
        { key: "failed" as const, label: "失败", count: countBy("failed") },
        { key: "skipped" as const, label: "跳过", count: countBy("skipped") },
      ].map((tab) => (
        <button
          key={tab.key}
          className={`pill-tab ${filter === tab.key ? "active" : ""}`}
          onClick={() => setFilter(tab.key)}
        >
          {tab.label}{" "}
          <span style={{ fontVariantNumeric: "tabular-nums", opacity: 0.7 }}>
            {tab.count}
          </span>
        </button>
      ))}
    </div>
  );

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h2 className="page-title">{tr("签到记录")}</h2>
        <button
          onClick={handleTriggerAll}
          disabled={triggering}
          className="btn btn-soft-primary"
        >
          {triggering ? (
            <>
              <span className="spinner spinner-sm" />
              触发中...
            </>
          ) : (
            "运行所有签到"
          )}
        </button>
      </div>

      <ResponsiveFilterPanel
        isMobile={isMobile}
        mobileOpen={showFilters}
        onMobileOpen={() => setShowFilters(true)}
        onMobileClose={() => setShowFilters(false)}
        mobileTitle="筛选签到记录"
        mobileContent={(
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {timeRangeControls}
            {hasInvalidTimeRange && (
              <div className="alert alert-error">
                结束时间必须晚于开始时间
              </div>
            )}
            {filterTabs}
          </div>
        )}
        desktopContent={(
          <div className="toolbar" style={{ marginBottom: "12px" }}>
            <div style={{ minWidth: 280 }}>{filterTabs}</div>
            <div
              style={{
                flex: "0 0 auto",
                display: "flex",
                alignItems: "center",
                gap: 10,
              }}
            >
              {timeRangeControls}
            </div>
            {hasInvalidTimeRange && (
              <div className="alert alert-error" style={{ width: "100%" }}>
                结束时间必须晚于开始时间
              </div>
            )}
          </div>
        )}
      />

      <div
        className="card"
        style={{
          overflowX: "auto",
          borderTopLeftRadius: 0,
          borderTopRightRadius: 0,
        }}
      >
        {loading ? (
          <div
            style={{
              padding: 24,
              display: "flex",
              flexDirection: "column",
              gap: 10,
            }}
          >
            {[...Array(5)].map((_, i) => (
              <div key={i} style={{ display: "flex", gap: 16 }}>
                <div className="skeleton" style={{ width: 120, height: 16 }} />
                <div className="skeleton" style={{ width: 80, height: 16 }} />
                <div className="skeleton" style={{ width: 120, height: 16 }} />
                <div className="skeleton" style={{ width: 70, height: 16 }} />
                <div className="skeleton" style={{ flex: 1, height: 16 }} />
                <div className="skeleton" style={{ width: 60, height: 16 }} />
              </div>
            ))}
          </div>
        ) : isMobile ? (
          <div className="mobile-card-list">
            {filtered.map((log: any) => {
              const status = getStatus(log);
              const reason = getFailureReason(log);
              const isExpanded =
                expandedLogId === (log.checkin_logs?.id || log.id);
              const logId = log.checkin_logs?.id || log.id;
              return (
                <MobileCard
                  key={logId}
                  title={log.accounts?.username || "未知"}
                  headerActions={
                    <span
                      className={`badge ${statusClass(status)}`}
                      style={{ fontSize: 10 }}
                    >
                      {statusLabel(status)}
                    </span>
                  }
                  footerActions={
                    <button
                      type="button"
                      className="btn btn-link"
                      onClick={() =>
                        setExpandedLogId(isExpanded ? null : logId)
                      }
                    >
                      {isExpanded ? "收起" : "详情"}
                    </button>
                  }
                >
                  <MobileField
                    label="时间"
                    value={formatCheckinLogTime(
                      log.checkin_logs?.createdAt || log.createdAt,
                    )}
                  />
                  <MobileField
                    label="站点"
                    value={
                      log.sites?.url ? (
                        <a
                          href={log.sites.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="badge-link"
                        >
                          <span
                            className="badge badge-muted"
                            style={{ fontSize: 11 }}
                          >
                            {log.sites?.name || "-"}
                          </span>
                        </a>
                      ) : (
                        <span
                          className="badge badge-muted"
                          style={{ fontSize: 11 }}
                        >
                          {log.sites?.name || "-"}
                        </span>
                      )
                    }
                  />
                  <MobileField
                    label="分类"
                    value={
                      reason ? (
                        <span
                          className="badge badge-info"
                          data-tooltip={reason.detailHint}
                        >
                          {reason.title}
                        </span>
                      ) : (
                        <span className="badge badge-muted">-</span>
                      )
                    }
                  />
                  <MobileField
                    label="奖励"
                    value={log.checkin_logs?.reward || "-"}
                  />
                  {isExpanded ? (
                    <div className="mobile-card-extra">
                      <MobileField
                        label="信息"
                        stacked
                        value={log.checkin_logs?.message || log.message}
                      />
                      <MobileField
                        label="建议"
                        stacked
                        value={reason?.actionHint || "-"}
                      />
                    </div>
                  ) : null}
                </MobileCard>
              );
            })}
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>时间</th>
                <th>账号</th>
                <th>站点</th>
                <th>状态</th>
                <th>分类</th>
                <th>信息</th>
                <th>建议</th>
                <th>奖励</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((log: any) => {
                const status = getStatus(log);
                const reason = getFailureReason(log);
                return (
                  <tr key={log.checkin_logs?.id || log.id}>
                    <td style={{ fontSize: 12, whiteSpace: "nowrap" }}>
                      {formatCheckinLogTime(
                        log.checkin_logs?.createdAt || log.createdAt,
                      )}
                    </td>
                    <td
                      style={{
                        fontWeight: 600,
                        color: "var(--color-text-primary)",
                      }}
                    >
                      {log.accounts?.username || "未知"}
                    </td>
                    <td>
                      {log.sites?.url ? (
                        <a
                          href={log.sites.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="badge-link"
                        >
                          <span
                            className="badge badge-muted"
                            style={{ fontSize: 11 }}
                          >
                            {log.sites?.name || "-"}
                          </span>
                        </a>
                      ) : (
                        <span
                          className="badge badge-muted"
                          style={{ fontSize: 11 }}
                        >
                          {log.sites?.name || "-"}
                        </span>
                      )}
                    </td>
                    <td>
                      <span className={`badge ${statusClass(status)}`}>
                        {statusLabel(status)}
                      </span>
                    </td>
                    <td>
                      {reason ? (
                        <span
                          className="badge badge-info"
                          data-tooltip={reason.detailHint}
                        >
                          {reason.title}
                        </span>
                      ) : (
                        <span className="badge badge-muted">-</span>
                      )}
                    </td>
                    <td style={{ maxWidth: 360 }}>
                      <span
                        style={{
                          display: "block",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {log.checkin_logs?.message || log.message}
                      </span>
                    </td>
                    <td style={{ maxWidth: 220 }}>
                      <span
                        style={{
                          display: "block",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                          color: "var(--color-text-secondary)",
                          fontSize: 12,
                        }}
                        data-tooltip={reason?.detailHint || ""}
                      >
                        {reason?.actionHint || "-"}
                      </span>
                    </td>
                    <td>{log.checkin_logs?.reward || "-"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        {!loading && filtered.length === 0 && (
          <div className="empty-state">
            <svg
              className="empty-state-icon"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1}
                d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <div className="empty-state-title">暂无签到记录</div>
            <div className="empty-state-desc">点击“运行所有签到”开始执行</div>
          </div>
        )}
      </div>
    </div>
  );
}
