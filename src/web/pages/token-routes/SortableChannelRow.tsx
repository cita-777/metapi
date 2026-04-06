import { useState, type CSSProperties } from 'react';
import ModernSelect from '../../components/ModernSelect.js';
import type { SortableChannelRowProps } from './types.js';
import {
  buildFixedTokenOptionDescription,
  buildFixedTokenOptionLabel,
  describeTokenBinding,
  resolveTokenBindingConnectionMode,
} from './tokenBindingPresentation.js';
import { getChannelDecisionState, getPriorityTagStyle, getProbabilityColor } from './utils.js';

function getRouteUnitStrategyLabel(strategy: string | null | undefined): string {
  return strategy === 'stick_until_unavailable' ? '单个用到不可用再切' : '轮询';
}

function formatRouteUnitMemberLabel(member: { accountId: number; username: string | null; siteName: string | null }): string {
  const accountLabel = member.username?.trim() || `account-${member.accountId}`;
  const siteLabel = member.siteName?.trim();
  return siteLabel ? `${accountLabel} @ ${siteLabel}` : accountLabel;
}

export function SortableChannelRow({
  channel,
  displayPriority,
  showPriorityBadge = true,
  dragging = false,
  dragHandleProps,
  dragHandleRef,
  decisionCandidate,
  isExactRoute,
  loadingDecision,
  isSavingPriority,
  readOnly = false,
  channelManagementDisabled = false,
  dragInProgress = false,
  mobile = false,
  tokenOptions,
  activeTokenId,
  isUpdatingToken,
  onTokenDraftChange,
  onSaveToken,
  onDeleteChannel,
  onToggleEnabled,
  onSiteBlockModel,
}: SortableChannelRowProps) {
  const resolvedPriority = displayPriority ?? channel.priority ?? 0;
  const managementLocked = readOnly || channelManagementDisabled;
  const suppressTooltips = dragInProgress || dragging;
  const rowTransition = [
    'box-shadow 180ms ease',
    'background-color 180ms ease',
    'border-color 180ms ease',
    'opacity 180ms ease',
  ].filter(Boolean).join(', ');
  const dragHandleStyle: CSSProperties = {
    width: 22,
    minWidth: 22,
    height: 22,
    padding: 0,
    border: `1px solid ${dragging ? 'color-mix(in srgb, var(--color-info) 34%, var(--color-border-light))' : 'var(--color-border-light)'}`,
    borderRadius: 10,
    backgroundColor: dragging
      ? 'color-mix(in srgb, var(--color-bg-card) 80%, var(--color-info) 20%)'
      : 'color-mix(in srgb, var(--color-bg-card) 90%, white 10%)',
    boxShadow: 'inset 0 1px 0 rgba(255, 255, 255, 0.62)',
    color: dragging ? 'var(--color-text-primary)' : 'var(--color-text-muted)',
    cursor: isSavingPriority || managementLocked ? 'not-allowed' : 'grab',
    opacity: managementLocked ? 0.65 : 1,
    transition: 'background-color 0.16s ease, border-color 0.16s ease, box-shadow 0.16s ease, color 0.16s ease',
  };

  const rowStyle: CSSProperties = {
    transition: rowTransition || undefined,
    opacity: dragging ? 0.92 : channel.enabled === false ? 0.56 : 1,
    display: 'grid',
    gridTemplateColumns: managementLocked || mobile ? 'minmax(0, 1fr)' : 'minmax(0, 1fr) auto auto auto',
    alignItems: mobile ? 'stretch' : 'center',
    gap: mobile ? 8 : 6,
    padding: mobile ? '8px 9px' : '5px 8px',
    border: `1px solid ${dragging ? 'color-mix(in srgb, var(--color-info) 38%, var(--color-border-light))' : 'color-mix(in srgb, var(--color-border-light) 92%, transparent)'}`,
    borderRadius: 14,
    backgroundColor: dragging
      ? 'color-mix(in srgb, var(--color-bg-card) 82%, var(--color-info) 18%)'
      : 'color-mix(in srgb, var(--color-bg-card) 96%, white 4%)',
    boxShadow: dragging
      ? '0 18px 34px rgba(15, 23, 42, 0.12)'
      : '0 10px 22px rgba(15, 23, 42, 0.04), inset 0 1px 0 rgba(255, 255, 255, 0.7)',
  };

  const decisionState = getChannelDecisionState(decisionCandidate, channel, isExactRoute, loadingDecision);
  const tokenBinding = describeTokenBinding(
    tokenOptions,
    activeTokenId,
    channel.token?.name ?? null,
    {
      connectionMode: resolveTokenBindingConnectionMode(channel.account),
      accountName: channel.account?.username || `account-${channel.accountId}`,
    },
  );
  const routeUnit = channel.routeUnit ?? null;
  const routeUnitName = routeUnit?.name?.trim() || 'OAuth 路由池';
  const routeUnitStrategyLabel = routeUnit ? getRouteUnitStrategyLabel(routeUnit.strategy) : '';
  const routeUnitMemberSummary = routeUnit?.members?.length
    ? routeUnit.members.map((member) => formatRouteUnitMemberLabel(member)).join('、')
    : null;
  const routeUnitMemberSummaryText = routeUnitMemberSummary ? `成员：${routeUnitMemberSummary}` : null;

  const [mobileDetailsOpen, setMobileDetailsOpen] = useState(false);

  if (mobile) {
    return (
      <div data-layer-root style={{ ...rowStyle, display: 'block' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
          <button
            type="button"
            ref={dragHandleRef}
            {...dragHandleProps}
            disabled={isSavingPriority || managementLocked}
            className="btn btn-ghost"
            style={{
              marginTop: 2,
              ...dragHandleStyle,
            }}
            data-tooltip={suppressTooltips ? undefined : (managementLocked ? '该路由当前不可编辑优先级' : '拖拽调整优先级桶')}
            aria-label="拖拽调整优先级桶"
          >
            <svg width="12" height="12" fill="currentColor" viewBox="0 0 12 12" aria-hidden>
              <circle cx="3" cy="2" r="1" />
              <circle cx="9" cy="2" r="1" />
              <circle cx="3" cy="6" r="1" />
              <circle cx="9" cy="6" r="1" />
              <circle cx="3" cy="10" r="1" />
              <circle cx="9" cy="10" r="1" />
            </svg>
          </button>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, minWidth: 0, flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
              {showPriorityBadge ? (
                <span
                  className="badge"
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    letterSpacing: 0.1,
                    ...getPriorityTagStyle(resolvedPriority),
                  }}
                >
                  P{resolvedPriority}
                </span>
              ) : null}

              <span style={{ fontWeight: 600, color: 'var(--color-text-primary)', fontSize: 14, minWidth: 0 }}>
                {channel.account?.username || `account-${channel.accountId}`}
              </span>

              <span className="badge badge-muted" style={{ fontSize: 10 }}>
                {channel.site?.name || 'unknown'}
              </span>

              <span style={{ fontSize: 11, color: 'var(--color-text-muted)', marginLeft: 'auto' }}>
                成功/失败 <span style={{ color: 'var(--color-success)', fontWeight: 600 }}>{channel.successCount || 0}</span>
                <span style={{ color: 'var(--color-text-muted)', margin: '0 2px' }}>/</span>
                <span style={{ color: 'var(--color-danger)', fontWeight: 600 }}>{channel.failCount || 0}</span>
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexWrap: 'wrap' }}>
              <span
                className="badge"
                style={{
                  fontSize: 10,
                  background: tokenBinding.badgeTone === 'info'
                    ? 'color-mix(in srgb, var(--color-info) 15%, transparent)'
                    : 'color-mix(in srgb, var(--color-warning) 15%, transparent)',
                  color: tokenBinding.badgeTone === 'info' ? 'var(--color-info)' : 'var(--color-warning)',
                }}
              >
                {tokenBinding.bindingModeLabel}
              </span>

              <span
                className="badge"
                style={{
                  fontSize: 10,
                  background: 'var(--color-info-soft)',
                  color: 'var(--color-info)',
                  maxWidth: 220,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
                data-tooltip={suppressTooltips ? undefined : `当前生效：${tokenBinding.effectiveTokenName}`}
              >
                当前生效：{tokenBinding.effectiveTokenName}
              </span>

              {channel.sourceModel ? (
                <span className="badge badge-info" style={{ fontSize: 10 }}>
                  {channel.sourceModel}
                </span>
              ) : null}

              {channel.manualOverride ? (
                <span
                  className="badge badge-warning"
                  style={{ fontSize: 10 }}
                  data-tooltip={suppressTooltips ? undefined : '该通道由用户手动添加，而非系统自动生成'}
                >
                  手动配置
                </span>
              ) : null}

              {routeUnit ? (
                <>
                  <span className="badge badge-muted" style={{ fontSize: 10 }}>
                    OAuth 路由池
                  </span>
                  <span className="badge badge-info" style={{ fontSize: 10 }}>
                    {routeUnitName}
                  </span>
                  <span className="badge badge-muted" style={{ fontSize: 10 }}>
                    {routeUnit.memberCount} 成员
                  </span>
                  <span className="badge badge-muted" style={{ fontSize: 10 }}>
                    {routeUnitStrategyLabel}
                  </span>
                </>
              ) : null}
            </div>

            {routeUnitMemberSummaryText ? (
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 11, color: 'var(--color-text-muted)', whiteSpace: 'nowrap' }}>
                  成员摘要（{routeUnit?.memberCount || 0} 个成员 · {routeUnitStrategyLabel}）
                </span>
                <span style={{ fontSize: 11, color: 'var(--color-text-secondary)', lineHeight: 1.45 }}>
                  {routeUnitMemberSummaryText}
                </span>
              </div>
            ) : null}

            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 11, color: 'var(--color-text-muted)', whiteSpace: 'nowrap' }}>选中概率</span>
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: 5, minWidth: 96 }}>
                <div
                  data-tooltip={suppressTooltips ? undefined : (decisionState.probability <= 0 ? decisionState.reasonText : undefined)}
                  style={{
                    width: 60,
                    height: 4,
                    background: 'color-mix(in srgb, var(--color-border) 88%, white 12%)',
                    borderRadius: 999,
                    overflow: 'hidden',
                  }}
                >
                  <div
                    style={{
                      width: `${Math.max(0, Math.min(100, decisionState.probability))}%`,
                      height: '100%',
                      background: getProbabilityColor(decisionState.probability),
                      borderRadius: 999,
                      transition: 'width 0.24s ease, background-color 0.18s ease',
                    }}
                  />
                </div>
                <span
                  data-tooltip={suppressTooltips ? undefined : (decisionState.probability <= 0 ? decisionState.reasonText : undefined)}
                  style={{
                    fontSize: 11,
                    color: decisionState.probability > 0 ? 'var(--color-text-secondary)' : decisionState.reasonColor,
                    fontVariantNumeric: 'tabular-nums',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {decisionState.probability.toFixed(1)}%
                </span>
              </div>

              {!managementLocked && (
                <button
                  type="button"
                  className="btn btn-link"
                  onClick={() => setMobileDetailsOpen((current) => !current)}
                  style={{ marginLeft: 'auto' }}
                >
                  {mobileDetailsOpen ? '收起配置' : '配置通道'}
                </button>
              )}
            </div>

            {!managementLocked && mobileDetailsOpen && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, paddingTop: 6, borderTop: '1px solid var(--color-border-light)' }}>
                <div style={{ width: '100%' }}>
                  <ModernSelect
                    size="sm"
                    value={String(activeTokenId || 0)}
                    onChange={(nextValue) => onTokenDraftChange(channel.id, Number.parseInt(nextValue, 10) || 0)}
                    disabled={isUpdatingToken}
                    options={[
                      {
                        value: '0',
                        label: tokenBinding.followOptionLabel,
                        description: tokenBinding.followOptionDescription,
                      },
                      ...tokenOptions.map((token) => ({
                        value: String(token.id),
                        label: buildFixedTokenOptionLabel(token, { includeDefaultTag: true }),
                        description: buildFixedTokenOptionDescription(token),
                      })),
                    ]}
                    placeholder="选择令牌绑定方式"
                  />
                  <div style={{ marginTop: 3, fontSize: 10.5, color: 'var(--color-text-muted)', lineHeight: 1.35 }}>
                    {tokenBinding.helperText}
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 10, flexWrap: 'wrap' }}>
                  <button
                    onClick={onSaveToken}
                    disabled={isUpdatingToken}
                    className="btn btn-link btn-link-info"
                  >
                    {isUpdatingToken ? <span className="spinner spinner-sm" /> : '保存'}
                  </button>

                  <button
                    onClick={() => onToggleEnabled(channel.enabled === false)}
                    className={`btn btn-link ${channel.enabled === false ? 'btn-link-info' : 'btn-link-warning'}`}
                  >
                    {channel.enabled === false ? '启用' : '禁用'}
                  </button>

                  {onSiteBlockModel && channel.site?.id ? (
                    <button
                      onClick={onSiteBlockModel}
                      className="btn btn-link btn-link-warning"
                    >
                      站点屏蔽
                    </button>
                  ) : null}

                  <button
                    onClick={onDeleteChannel}
                    className="btn btn-link btn-link-danger"
                  >
                    移除
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div data-layer-root style={rowStyle}>
      <div style={{ display: 'flex', alignItems: mobile ? 'stretch' : 'center', flexDirection: mobile ? 'column' : 'row', gap: 6, fontSize: 12, flexWrap: 'wrap', minWidth: 0 }}>
        <button
          type="button"
          ref={dragHandleRef}
          {...dragHandleProps}
          disabled={isSavingPriority || managementLocked}
          className="btn btn-ghost"
          style={dragHandleStyle}
          data-tooltip={suppressTooltips ? undefined : (managementLocked ? '该路由当前不可编辑优先级' : '拖拽调整优先级桶')}
          aria-label="拖拽调整优先级桶"
        >
          <svg width="12" height="12" fill="currentColor" viewBox="0 0 12 12" aria-hidden>
            <circle cx="3" cy="2" r="1" />
            <circle cx="9" cy="2" r="1" />
            <circle cx="3" cy="6" r="1" />
            <circle cx="9" cy="6" r="1" />
            <circle cx="3" cy="10" r="1" />
            <circle cx="9" cy="10" r="1" />
          </svg>
        </button>

        {showPriorityBadge ? (
          <span
            className="badge"
            style={{
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: 0.1,
              ...getPriorityTagStyle(resolvedPriority),
            }}
          >
            P{resolvedPriority}
          </span>
        ) : null}

        <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
          {channel.account?.username || `account-${channel.accountId}`}
        </span>

        <span className="badge badge-muted" style={{ fontSize: 10 }}>
          {channel.site?.name || 'unknown'}
        </span>

        <span
          className="badge"
          style={{
            fontSize: 10,
            background: tokenBinding.badgeTone === 'info'
              ? 'color-mix(in srgb, var(--color-info) 15%, transparent)'
              : 'color-mix(in srgb, var(--color-warning) 15%, transparent)',
            color: tokenBinding.badgeTone === 'info' ? 'var(--color-info)' : 'var(--color-warning)',
          }}
        >
          {tokenBinding.bindingModeLabel}
        </span>

        <span
          className="badge"
          style={{
            fontSize: 10,
            background: 'var(--color-info-soft)',
            color: 'var(--color-info)',
            maxWidth: 220,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
          data-tooltip={suppressTooltips ? undefined : `当前生效：${tokenBinding.effectiveTokenName}`}
        >
          当前生效：{tokenBinding.effectiveTokenName}
        </span>

        {channel.sourceModel ? (
          <span className="badge badge-info" style={{ fontSize: 10 }}>
            {channel.sourceModel}
          </span>
        ) : null}

        {channel.manualOverride ? (
          <span
            className="badge badge-warning"
            style={{ fontSize: 10 }}
            data-tooltip={suppressTooltips ? undefined : '该通道由用户手动添加，而非系统自动生成'}
          >
            手动配置
          </span>
        ) : null}

        {channel.enabled === false ? (
          <span className="badge badge-muted" style={{ fontSize: 10 }}>已禁用</span>
        ) : null}

        {routeUnit ? (
          <>
            <span className="badge badge-muted" style={{ fontSize: 10 }}>
              OAuth 路由池
            </span>
            <span className="badge badge-info" style={{ fontSize: 10 }}>
              {routeUnitName}
            </span>
            <span className="badge badge-muted" style={{ fontSize: 10 }}>
              {routeUnit.memberCount} 成员
            </span>
            <span className="badge badge-muted" style={{ fontSize: 10 }}>
              {routeUnitStrategyLabel}
            </span>
          </>
        ) : null}

        {routeUnitMemberSummaryText ? (
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6, width: '100%', flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, color: 'var(--color-text-muted)', whiteSpace: 'nowrap' }}>
              成员摘要（{routeUnit?.memberCount || 0} 个成员 · {routeUnitStrategyLabel}）
            </span>
            <span style={{ fontSize: 11, color: 'var(--color-text-secondary)', lineHeight: 1.45 }}>
              {routeUnitMemberSummaryText}
            </span>
          </div>
        ) : null}

        <div style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%', marginTop: mobile ? 0 : 1, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11, color: 'var(--color-text-muted)', whiteSpace: 'nowrap' }}>选中概率</span>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 5, minWidth: 96 }}>
            <div
              data-tooltip={suppressTooltips ? undefined : (decisionState.probability <= 0 ? decisionState.reasonText : undefined)}
              style={{
                width: 60,
                height: 4,
                background: 'color-mix(in srgb, var(--color-border) 88%, white 12%)',
                borderRadius: 999,
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  width: `${Math.max(0, Math.min(100, decisionState.probability))}%`,
                  height: '100%',
                  background: getProbabilityColor(decisionState.probability),
                  borderRadius: 999,
                  transition: 'width 0.24s ease, background-color 0.18s ease',
                }}
              />
            </div>
            <span
              data-tooltip={suppressTooltips ? undefined : (decisionState.probability <= 0 ? decisionState.reasonText : undefined)}
              style={{
                fontSize: 11,
                color: decisionState.probability > 0 ? 'var(--color-text-secondary)' : decisionState.reasonColor,
                fontVariantNumeric: 'tabular-nums',
                whiteSpace: 'nowrap',
              }}
            >
              {decisionState.probability.toFixed(1)}%
            </span>
          </div>

          <span style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>成功/失败</span>
          <span style={{ fontSize: 11 }}>
            <span style={{ color: 'var(--color-success)', fontWeight: 600 }}>{channel.successCount || 0}</span>
            <span style={{ color: 'var(--color-text-muted)', margin: '0 2px' }}>/</span>
            <span style={{ color: 'var(--color-danger)', fontWeight: 600 }}>{channel.failCount || 0}</span>
          </span>
        </div>
      </div>

      {!managementLocked ? (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ minWidth: 220, flex: 1 }}>
              <ModernSelect
                size="sm"
                value={String(activeTokenId || 0)}
                onChange={(nextValue) => onTokenDraftChange(channel.id, Number.parseInt(nextValue, 10) || 0)}
                disabled={isUpdatingToken}
                options={[
                  {
                    value: '0',
                    label: tokenBinding.followOptionLabel,
                    description: tokenBinding.followOptionDescription,
                  },
                  ...tokenOptions.map((token) => ({
                    value: String(token.id),
                    label: buildFixedTokenOptionLabel(token, { includeDefaultTag: true }),
                    description: buildFixedTokenOptionDescription(token),
                  })),
                ]}
                placeholder="选择令牌绑定方式"
              />
              <div style={{ marginTop: 3, fontSize: 10.5, color: 'var(--color-text-muted)', lineHeight: 1.35 }}>
                {tokenBinding.helperText}
              </div>
            </div>
            <button
              onClick={onSaveToken}
              disabled={isUpdatingToken}
              className="btn btn-link btn-link-info"
            >
              {isUpdatingToken ? <span className="spinner spinner-sm" /> : '保存'}
            </button>
          </div>

          <button
            onClick={() => onToggleEnabled(channel.enabled === false)}
            className={`btn btn-link ${channel.enabled === false ? 'btn-link-info' : 'btn-link-warning'}`}
            data-tooltip={suppressTooltips ? undefined : (channel.enabled === false ? '启用此通道' : '禁用此通道')}
          >
            {channel.enabled === false ? '启用' : '禁用'}
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
            {onSiteBlockModel && channel.site?.id ? (
              <button
                onClick={onSiteBlockModel}
                className="btn btn-link btn-link-warning"
                data-tooltip={suppressTooltips ? undefined : `将此模型加入站点「${channel.site?.name || '未知'}」的禁用列表，rebuild 后该站点的此模型通道将不再生成`}
              >
                站点屏蔽
              </button>
            ) : null}

            <button
              onClick={onDeleteChannel}
              className="btn btn-link btn-link-danger"
            >
              移除
            </button>
          </div>
        </>
      ) : null}
    </div>
  );
}
